//===----------------------------------------------------------------------===//
//
// This source file is part of the Swift HTTP Server open source project
//
// Copyright (c) 2026 Apple Inc. and the Swift HTTP Server project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of Swift HTTP Server project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

// PROTOTYPE: HTTP/3 on the lightweight HTTP/3 streams of `NIOHTTP3` (`HTTP3ServerConsumer`), instead of a `Channel` and a
// `NIOAsyncChannel` per request stream.
//
// - Request streams are served by one `HTTP3ServerConsumer` per connection. It hands each request head to the
//   connection's task, which runs the request handler in a child task, like the channel-based path does.
// - All of it runs on the listener's event loop: the tasks prefer an `EventLoopTaskExecutor`, so the handler
//   touches its stream directly, with no hops to and from the event loop.
// - Response parts are gathered and sent together: a response that's written in one go leaves in one flush,
//   so in one set of packets.
//
// Not production ready: no read timeouts, no write back pressure (writes never wait: the QUIC stream queues what
// flow control doesn't let through yet), no HTTP datagrams, and only minimal error handling.

#if HTTP3
import HTTP3
import HTTPTypes
import Logging
import NIOCore
import NIOHTTP3
import NIOHTTPTypes
import NIOPosix
import NIOQUIC
import NIOQUICHelpers
import ServiceLifecycle

/// Runs jobs on a NIO event loop.
@available(anyAppleOS 27.0, *)
final class EventLoopTaskExecutor: TaskExecutor, @unchecked Sendable {
    let eventLoop: any EventLoop

    init(eventLoop: any EventLoop) {
        self.eventLoop = eventLoop
    }

    func enqueue(_ job: consuming ExecutorJob) {
        let job = UnownedJob(job)
        self.eventLoop.execute {
            job.runSynchronously(on: self.asUnownedTaskExecutor())
        }
    }
}

/// A single consumer queue, confined to an event loop: the producer is the event loop, the consumer a task which
/// runs on it.
@available(anyAppleOS 27.0, *)
final class LightweightHTTP3Queue<Element: Sendable>: @unchecked Sendable {
    private let eventLoop: any EventLoop
    private var pending = CircularBuffer<Element>()
    private var waiter: UnsafeContinuation<Element?, Never>?
    private var isFinished = false

    init(eventLoop: any EventLoop) {
        self.eventLoop = eventLoop
    }

    func yield(_ element: Element) {
        self.eventLoop.assertInEventLoop()
        if let waiter = self.waiter.take() {
            waiter.resume(returning: element)
        } else {
            self.pending.append(element)
        }
    }

    func finish() {
        self.eventLoop.assertInEventLoop()
        self.isFinished = true
        self.waiter.take()?.resume(returning: nil)
    }

    /// The next element, or `nil` once the queue is finished. Must be called on the event loop.
    func next() async -> Element? {
        self.eventLoop.assertInEventLoop()
        if let element = self.pending.popFirst() {
            return element
        }
        if self.isFinished {
            return nil
        }
        return await withUnsafeContinuation { continuation in
            self.waiter = continuation
        }
    }
}

/// One HTTP/3 connection served on the lightweight HTTP/3 streams.
@available(anyAppleOS 27.0, *)
final class LightweightHTTP3Connection: @unchecked Sendable {
    struct InboundRequest: @unchecked Sendable {
        var head: HTTPRequest
        var stream: LightweightHTTP3Request
    }

    let eventLoop: any EventLoop
    let channel: any Channel
    let requests: LightweightHTTP3Queue<InboundRequest>
    /// Set once the consumer exists, which is right after this.
    var http3Connection: HTTP3Connection<LightweightHTTP3Consumer>!

    init(channel: any Channel) {
        self.eventLoop = channel.eventLoop
        self.channel = channel
        self.requests = LightweightHTTP3Queue(eventLoop: channel.eventLoop)
        channel.closeFuture.whenComplete { [requests] _ in
            requests.finish()
        }
    }
}

/// A request stream, between the consumer, which reads and writes it, and the task that runs its handler.
///
/// Confined to the connection's event loop: the handler's task runs on it.
@available(anyAppleOS 27.0, *)
final class LightweightHTTP3Request: @unchecked Sendable {
    /// Reading pauses once this much of the body is waiting for the handler.
    static var maximumBufferedBodyBytes: Int { 256 * 1024 }
    /// Written body bytes are sent straight away once this many are waiting.
    static var flushThreshold: Int { 64 * 1024 }

    let handle: QUICStreamHandle
    unowned let connection: LightweightHTTP3Connection

    // Inbound
    var body = ByteBuffer()
    private var receivedEnd = false
    private var deliveredEnd = false
    private var trailers: HTTPFields?
    private var readError: (any Error)?
    private var readWaiter: UnsafeContinuation<Void, any Error>?
    private var isReadingPaused = false

    // Outbound
    private var pendingHead: HTTPResponse?
    private var pendingInformational: [HTTPResponse] = []
    private var pendingBody: [ByteBuffer] = []
    private var pendingBodyBytes = 0
    private var pendingEnd = false
    private var pendingTrailers: HTTPFields?
    private var isFlushScheduled = false
    private var writeError: (any Error)?
    private(set) var finishedWriting = false

    // Lifecycle
    private var isClosed = false
    private var task: UnsafeCurrentTask?

    init(handle: QUICStreamHandle, connection: LightweightHTTP3Connection) {
        self.handle = handle
        self.connection = connection
    }

    var eventLoop: any EventLoop { self.connection.eventLoop }

    // MARK: Consumer side

    /// Takes body bytes the consumer read, returning how many it took.
    func receivedBody(_ bytes: borrowing RawSpan) -> Int {
        let room = Self.maximumBufferedBodyBytes - self.body.readableBytes
        guard room > 0 else {
            self.isReadingPaused = true
            return 0
        }
        let taken = min(room, bytes.byteCount)
        unsafe bytes.extracting(0..<taken).withUnsafeBytes { _ = self.body.writeBytes($0) }
        return taken
    }

    func receivedEnd(trailers: HTTPFields?) {
        self.receivedEnd = true
        self.trailers = trailers
    }

    func readFailed(_ error: any Error) {
        if self.readError == nil {
            self.readError = error
        }
    }

    /// Wakes the handler if it's waiting for the request.
    func wakeReader() {
        guard let waiter = self.readWaiter.take() else { return }
        if let error = self.readError {
            waiter.resume(throwing: error)
        } else {
            waiter.resume()
        }
    }

    func streamClosed(error: (any Error)?) {
        self.isClosed = true
        if !self.receivedEnd {
            self.readFailed(error ?? ChannelError.eof)
        }
        self.wakeReader()
        // The client went away before it got the whole response: cancel the handler, like the channel-based
        // path does.
        if !self.finishedWriting {
            self.task?.cancel()
        }
    }

    // MARK: Handler side

    func attach(task: UnsafeCurrentTask?) {
        self.task = task
    }

    func detach() {
        self.task = nil
    }

    /// The next part of the request body: a `.body` or the `.end`. `nil` once the end was delivered.
    func read() async throws -> HTTPRequestPart? {
        self.eventLoop.assertInEventLoop()
        while true {
            if self.body.readableBytes > 0 {
                let body = self.body
                self.body = ByteBuffer()
                if self.isReadingPaused {
                    self.resumeReading()
                }
                return .body(body)
            }
            if self.receivedEnd {
                if self.deliveredEnd {
                    return nil
                }
                self.deliveredEnd = true
                return .end(self.trailers)
            }
            if let error = self.readError {
                throw error
            }
            // Send whatever the handler has written before waiting for the client.
            try self.flush()
            try await withUnsafeThrowingContinuation { continuation in
                self.readWaiter = continuation
            }
        }
    }

    private func resumeReading() {
        self.isReadingPaused = false
        _ = try? self.connection.http3Connection.withRequest(self.handle) { request, stream in
            request.resumeReading()
            LightweightHTTP3Consumer.readRequest(&request, stream: &stream, connection: self.connection)
        }
    }

    func sendInformational(_ response: HTTPResponse) throws {
        try self.checkWritable()
        self.pendingInformational.append(response)
        try self.flush()
    }

    func sendHead(_ response: HTTPResponse) throws {
        try self.checkWritable()
        // Held back until there's more to send, so a whole response goes out together.
        self.pendingHead = response
    }

    func write(_ body: ByteBuffer) throws {
        try self.checkWritable()
        guard body.readableBytes > 0 else { return }
        self.pendingBody.append(body)
        self.pendingBodyBytes += body.readableBytes
        if self.pendingBodyBytes >= Self.flushThreshold {
            try self.flush()
        } else if !self.isFlushScheduled {
            // A handler which writes and finishes without suspending is flushed by `finish`, before this runs.
            self.isFlushScheduled = true
            self.eventLoop.execute {
                self.isFlushScheduled = false
                do {
                    try self.flush()
                } catch {
                    self.writeError = error
                }
            }
        }
    }

    func finish(trailers: HTTPFields?) throws {
        try self.checkWritable()
        self.pendingEnd = true
        self.pendingTrailers = trailers
        self.finishedWriting = true
        try self.flush()
    }

    /// Resets the stream and asks the client to stop sending.
    func abort(resetCode: QUICApplicationErrorCode, stopSendingCode: QUICApplicationErrorCode) {
        self.finishedWriting = true
        _ = try? self.connection.http3Connection.withRequest(self.handle) { _, stream in
            if stream.isReceiveOpen {
                stream.sendStopSending(code: stopSendingCode)
            }
            if stream.isSendOpen {
                stream.sendResetStream(code: resetCode)
            }
        }
    }

    /// Called when the handler returned: a response it didn't finish is cancelled.
    func handlerReturned() {
        if !self.finishedWriting {
            self.finishedWriting = true
            _ = try? self.connection.http3Connection.withRequest(self.handle) { request, stream in
                request.cancel(stream: &stream)
            }
        }
    }

    private func checkWritable() throws {
        if let error = self.writeError {
            throw error
        }
        if self.isClosed {
            throw ChannelError.ioOnClosedChannel
        }
    }

    private var hasPendingWrites: Bool {
        self.pendingHead != nil || !self.pendingInformational.isEmpty || !self.pendingBody.isEmpty || self.pendingEnd
    }

    /// Sends everything written so far, in one go.
    func flush() throws {
        guard self.hasPendingWrites else { return }
        let sent: Void? = try self.connection.http3Connection.withRequest(self.handle) { request, stream in
            for informational in self.pendingInformational {
                try request.writeResponseHead(informational, to: &stream)
            }
            self.pendingInformational.removeAll(keepingCapacity: true)
            if let head = self.pendingHead.take() {
                try request.writeResponseHead(head, to: &stream)
            }
            for body in self.pendingBody {
                try request.writeBody(body, to: &stream)
            }
            self.pendingBody.removeAll(keepingCapacity: true)
            self.pendingBodyBytes = 0
            if self.pendingEnd {
                self.pendingEnd = false
                try request.writeEnd(trailers: self.pendingTrailers.take(), to: &stream)
            }
        }
        if sent == nil {
            throw ChannelError.ioOnClosedChannel
        }
    }
}

/// The consumer of a server's HTTP/3 connection on the lightweight HTTP/3 streams.
@available(anyAppleOS 27.0, *)
struct LightweightHTTP3Consumer: HTTP3ServerConsumer {
    typealias RequestState = LightweightHTTP3Request?

    let http3Connection: HTTP3Connection<Self>
    let connection: LightweightHTTP3Connection

    func makeRequestState() -> RequestState {
        nil
    }

    func processRequest(_ request: inout HTTP3StreamState<RequestState>, stream: inout QUICStream<Self>) {
        Self.readRequest(&request, stream: &stream, connection: self.connection)
    }

    func requestStreamClosed(_ request: inout HTTP3StreamState<RequestState>, error: (any Error)?) {
        request.state?.streamClosed(error: error)
    }

    static func readRequest(
        _ request: inout HTTP3StreamState<RequestState>,
        stream: inout QUICStream<Self>,
        connection: LightweightHTTP3Connection
    ) {
        do {
            while let part = try request.readRequestPart(
                from: &stream,
                body: { bytes, state in
                    // Body bytes only come after the head, which made the state.
                    state?.receivedBody(bytes) ?? bytes.byteCount
                }
            ) {
                switch part {
                case .head(let head):
                    let inbound = LightweightHTTP3Request(handle: stream.handle, connection: connection)
                    request.state = inbound
                    connection.requests.yield(.init(head: head, stream: inbound))
                case .body:
                    ()
                case .end(let trailers):
                    request.state?.receivedEnd(trailers: trailers)
                }
            }
        } catch {
            request.state?.readFailed(error)
        }
        request.state?.wakeReader()
    }
}

@available(anyAppleOS 27.0, *)
extension NIOHTTPServer {
    /// Adds a child task to `group` that binds a QUIC listener at `address` on `eventLoop` and serves HTTP/3
    /// connections on it with the lightweight HTTP/3 streams, until the task is cancelled or the server shuts down
    /// gracefully.
    func addLightweightHTTP3Listener<Handler: NIOHTTPServerConnectionHandler>(
        to group: inout ThrowingDiscardingTaskGroup<any Error>,
        address: NIOCore.SocketAddress,
        eventLoop: any EventLoop,
        socket: HTTP3ListenerSocket,
        configuration: ListenerConfiguration.HTTP3,
        addressContinuation: AsyncThrowingStream<NIOCore.SocketAddress, any Error>.Continuation,
        connectionHandler: Handler
    ) {
        let executor = EventLoopTaskExecutor(eventLoop: eventLoop)
        group.addTask(name: "HTTP/3 (lightweight streams) over \(address) on \(eventLoop)") {
            // Everything below, down to the request handlers, runs on the event loop.
            try await withTaskExecutorPreference(executor) {
                try await self.withLightweightHTTP3Channel(
                    address: address,
                    eventLoop: eventLoop,
                    socket: socket,
                    configuration: configuration,
                    addressContinuation: addressContinuation
                ) { connections in
                    await withDiscardingTaskGroup { connectionGroup in
                        while let connection = await connections.next() {
                            connectionGroup.addTask {
                                await self.dispatchLightweightHTTP3Connection(connection, handler: connectionHandler)
                            }
                        }
                    }
                }
            }
        }
    }

    func dispatchLightweightHTTP3Connection<Handler: NIOHTTPServerConnectionHandler>(
        _ http3Connection: LightweightHTTP3Connection,
        handler: Handler
    ) async {
        let context = ConnectionContext(
            httpVersion: .http3,
            remoteAddress: nil,
            localAddress: nil,
            validatedPeerCertificateChain: nil
        )
        let connection = Connection(
            server: self,
            context: context,
            httpProtocol: .lightweightHTTP3(connection: http3Connection)
        )
        do {
            try await handler.handleConnection(connection: connection, context: context)
        } catch {
            self.logger.debug("Error thrown by connection handler", error: error)
        }
    }

    /// Runs each request of the connection in a child task, on the connection's event loop.
    func handleLightweightHTTP3Connection<Handler: HTTPServerRequestHandler>(
        connection: LightweightHTTP3Connection,
        handler: Handler,
        context: ConnectionContext
    ) async
    where
        Handler.RequestContext == RequestContext,
        Handler.Reader == Reader,
        Handler.ResponseSender == ResponseSender
    {
        await withDiscardingTaskGroup { requestGroup in
            while let inbound = await connection.requests.next() {
                requestGroup.addTask {
                    await self.handleLightweightHTTP3Request(inbound, handler: handler, context: context)
                }
            }
        }
    }

    private func handleLightweightHTTP3Request<Handler: HTTPServerRequestHandler>(
        _ inbound: LightweightHTTP3Connection.InboundRequest,
        handler: Handler,
        context: ConnectionContext
    ) async
    where
        Handler.RequestContext == RequestContext,
        Handler.Reader == Reader,
        Handler.ResponseSender == ResponseSender
    {
        let stream = inbound.stream
        unsafe withUnsafeCurrentTask { task in
            unsafe stream.attach(task: task)
        }

        let requestContext = RequestContext(
            connectionContext: context,
            channel: stream.connection.channel,
            lightweightHTTP3Request: stream
        )
        _ = await self.invokeHandler(
            request: inbound.head,
            requestContext: requestContext,
            requestReader: Reader(lightweightHTTP3Request: stream),
            responseSender: ResponseSender(lightweightHTTP3Request: stream),
            handler: handler
        )

        stream.detach()
        stream.handlerReturned()
    }

    /// Binds the QUIC listener, and runs `body` with the queue of its connections. The socket is closed when `body`
    /// returns or throws.
    func withLightweightHTTP3Channel(
        address: NIOCore.SocketAddress,
        eventLoop: any EventLoop,
        socket: HTTP3ListenerSocket,
        configuration: ListenerConfiguration.HTTP3,
        addressContinuation: AsyncThrowingStream<NIOCore.SocketAddress, any Error>.Continuation,
        _ body: (LightweightHTTP3Queue<LightweightHTTP3Connection>) async throws -> Void
    ) async throws {
        var bootstrap = DatagramBootstrap(group: eventLoop)
            .channelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)

        if socket.sharesPort {
            bootstrap = bootstrap.channelOption(ChannelOptions.socketOption(.so_reuseport), value: 1)
        }

        let quicChannel: any Channel
        let connections: LightweightHTTP3Queue<LightweightHTTP3Connection>

        do {
            (quicChannel, connections) = try await bootstrap.bind(to: address) { channel in
                channel.eventLoop.makeCompletedFuture {
                    // Set don't fragment on IP sockets for QUIC per RFC 9000, § 14.
                    switch address {
                    case .v4, .v6:
                        try QUICDontFragment.set(on: channel)
                    case .unixDomainSocket:
                        break
                    }
                    let connections = try self.setupLightweightQUICChannel(
                        channel: channel,
                        configuration: configuration,
                        socket: socket
                    )
                    return (channel, connections)
                }
            }
        } catch {
            addressContinuation.finish(throwing: error)
            throw error
        }

        try await withTaskCancellationHandler {
            try await withGracefulShutdownHandler {
                if Task.isCancelled || Task.isShuttingDownGracefully {
                    try? await quicChannel.closeFuture.get()
                    return
                }

                guard let localAddress = quicChannel.localAddress else {
                    addressContinuation.finish(throwing: ListeningAddressError.addressOrPortNotAvailable)
                    throw ListeningAddressError.addressOrPortNotAvailable
                }

                // A socket does not join its real reuseport group until it is bound, so this comes after the bind.
                if let socketGroup = socket.socketGroup {
                    do {
                        try await quicChannel.eventLoop.submit {
                            let adopted: Void? = try quicChannel.pipeline.syncOperations
                                .withUnsafeTransportIfAvailable(of: NIOBSDSocket.Handle.self) { socketFD in
                                    try socketGroup.socketBound(socketFD, socketIndex: socket.index)
                                }
                            guard adopted != nil else {
                                preconditionFailure("The channel does not expose its underlying socket handle.")
                            }
                        }.get()
                    } catch {
                        addressContinuation.finish(throwing: error)
                        try? await quicChannel.close()
                        throw error
                    }
                }

                addressContinuation.yield(localAddress)

                do {
                    try await body(connections)
                } catch {
                    try? await quicChannel.close()
                    throw error
                }

                try? await quicChannel.close()
            } onGracefulShutdown: {
                addressContinuation.finish(throwing: ListeningAddressError.serverClosed)
                quicChannel.pipeline.fireUserInboundEventTriggered(ChannelShouldQuiesceEvent())
            }
        } onCancel: {
            addressContinuation.finish(throwing: ListeningAddressError.serverClosed)
            quicChannel.close(promise: nil)
        }
    }

    func setupLightweightQUICChannel(
        channel: any Channel,
        configuration: ListenerConfiguration.HTTP3,
        socket: HTTP3ListenerSocket
    ) throws -> LightweightHTTP3Queue<LightweightHTTP3Connection> {
        let connections = LightweightHTTP3Queue<LightweightHTTP3Connection>(eventLoop: channel.eventLoop)
        channel.closeFuture.whenComplete { _ in
            connections.finish()
        }

        let quicConfiguration = QUICConfiguration(
            configuration.http3Configuration.quicConfiguration,
            authenticationConfiguration: configuration.authenticationConfiguration
        )
        let settings = HTTP3Settings(configuration.http3Configuration.connectionSettings)
        let logger = self.logger

        let connectionIDGenerator: any QUICConnectionID.Generator =
            if let group = socket.socketGroup {
                group.makeConnectionIDGenerator(socketIndex: socket.index)
            } else {
                QUICConnectionID.RandomGenerator()
            }

        let quicHandler = QUICHandler<LightweightHTTP3Consumer>(
            channel: channel,
            quicConfiguration: quicConfiguration,
            // TODO: mTLS is not yet supported by NIOQUIC so we don't specify a value for `asyncVerifier`.
            asyncVerifier: nil,
            authenticator: configuration.quicAuthenticator,
            logger: logger,
            connectionIDGenerator: connectionIDGenerator
        ) { quicConnection in
            let connection = LightweightHTTP3Connection(channel: quicConnection.channel)
            let consumer = LightweightHTTP3Consumer(
                http3Connection: .server(quicConnection, settings: settings, logger: logger),
                connection: connection
            )
            connection.http3Connection = consumer.http3Connection
            connections.yield(connection)
            return consumer
        }

        try channel.pipeline.syncOperations.addHandler(quicHandler)
        return connections
    }
}
#endif  // HTTP3
