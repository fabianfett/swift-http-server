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
// - The tasks prefer the listener's event loop as their `TaskExecutor`, if it is one: then the handler touches its
//   stream directly, with no hops to and from the event loop. Otherwise they run on the global concurrent executor,
//   and hop to the event loop to touch the stream. The state the consumer and the handler share is behind a lock,
//   so both work.
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
import Synchronization

/// A single consumer queue: the producer is the event loop, the consumer a task which runs anywhere.
@available(anyAppleOS 27.0, *)
final class LightweightHTTP3Queue<Element: Sendable>: Sendable {
    private struct State: ~Copyable {
        var pending = CircularBuffer<Element>()
        var waiter: Continuation<Element?, Never>?
        var isFinished = false
    }

    private let state = Mutex(State())

    init() {}

    func yield(_ element: Element) {
        let waiter = self.state.withLock { state in
            let waiter = state.waiter.take()
            if waiter == nil {
                state.pending.append(element)
            }
            return waiter
        }
        waiter?.resume(returning: element)
    }

    func finish() {
        let waiter = self.state.withLock { state in
            state.isFinished = true
            return state.waiter.take()
        }
        waiter?.resume(returning: nil)
    }

    /// The next element, or `nil` once the queue is finished.
    func next() async -> Element? {
        let next = self.state.withLock { state -> Element?? in
            if let element = state.pending.popFirst() {
                return element
            }
            if state.isFinished {
                return .some(nil)
            }
            return nil
        }
        if let next {
            return next
        }
        return await withContinuation(of: Element?.self) { continuation in
            var continuation = Optional(continuation)
            let next = self.state.withLock { state -> Element?? in
                if let element = state.pending.popFirst() {
                    return element
                }
                if state.isFinished {
                    return .some(nil)
                }
                precondition(state.waiter == nil, "\(Self.self) only has a single consumer")
                state.waiter = continuation.take()
                return nil
            }
            if let next {
                continuation?.resume(returning: next)
            }
        }
    }
}

/// One HTTP/3 connection served on the lightweight HTTP/3 streams.
@available(anyAppleOS 27.0, *)
final class LightweightHTTP3Connection: Sendable {
    struct InboundRequest: Sendable {
        var head: HTTPRequest
        var stream: LightweightHTTP3Request
    }

    let eventLoop: any EventLoop
    let channel: any Channel
    let requests: LightweightHTTP3Queue<InboundRequest>
    /// Only usable on ``eventLoop``.
    let http3Connection: NIOLoopBound<HTTP3Connection<LightweightHTTP3Consumer>>

    init(channel: any Channel, http3Connection: HTTP3Connection<LightweightHTTP3Consumer>) {
        self.eventLoop = channel.eventLoop
        self.channel = channel
        self.requests = LightweightHTTP3Queue()
        self.http3Connection = NIOLoopBound(http3Connection, eventLoop: channel.eventLoop)
        channel.closeFuture.whenComplete { [requests] _ in
            requests.finish()
        }
    }
}

/// A request stream, between the consumer, which reads and writes it on the connection's event loop, and the task
/// that runs its handler, which may run anywhere.
///
/// They share the state behind ``state``. The stream itself is only touched on the event loop: directly if the
/// handler's task runs there, after a hop otherwise.
@available(anyAppleOS 27.0, *)
final class LightweightHTTP3Request: Sendable {
    /// Reading pauses once this much of the body is waiting for the handler.
    static var maximumBufferedBodyBytes: Int { 256 * 1024 }
    /// Written body bytes are sent straight away once this many are waiting.
    static var flushThreshold: Int { 64 * 1024 }

    /// What the handler wrote, and which isn't sent yet.
    private struct PendingWrites {
        var informational: [HTTPResponse] = []
        var head: HTTPResponse?
        var body: [ByteBuffer] = []
        var bodyBytes = 0
        var end = false
        var trailers: HTTPFields?

        var isEmpty: Bool {
            self.head == nil && self.informational.isEmpty && self.body.isEmpty && !self.end
        }
    }

    private struct State: ~Copyable {
        // Inbound
        var body = ByteBuffer()
        var receivedEnd = false
        var deliveredEnd = false
        var trailers: HTTPFields?
        var readError: (any Error)?
        var readWaiter: Continuation<Void, Never>?
        var isReadingPaused = false

        // Outbound
        var pending = PendingWrites()
        var isFlushScheduled = false
        var writeError: (any Error)?
        var finishedWriting = false

        // Lifecycle
        var isClosed = false
        /// Whether ``LightweightHTTP3Request/task`` is set.
        var hasTask = false
        /// Set while the event loop cancels the handler's task: the task must not end until it's done.
        var isCancellingTask = false
        /// The handler's task, waiting for the cancellation to be done before it ends.
        var cancellationWaiter: Continuation<Void, Never>?

        var hasReadableEvent: Bool {
            self.body.readableBytes > 0 || self.receivedEnd || self.readError != nil
        }
    }

    /// When to send what the handler wrote.
    private enum Flush {
        /// Not until there's more.
        case later
        /// Soon, after the handler had the chance to write more.
        case soon
        /// Straight away.
        case now
    }

    /// What to do once the lock is released.
    private enum FlushAction {
        case none
        case flushNow
        case scheduleFlush
    }

    let handle: QUICStreamHandle
    unowned let connection: LightweightHTTP3Connection
    private let state = Mutex(State())
    /// The handler's task, while it runs, so the event loop can cancel it if the client goes away.
    ///
    /// Only touched with ``state`` locked. It's outside of ``state`` because `UnsafeCurrentTask` isn't `Sendable`,
    /// and there's no `Sendable` way to cancel a child task from outside. Cancelling a task is safe from any thread,
    /// as long as the task is alive: ``State/isCancellingTask`` keeps it from ending while it's cancelled.
    private nonisolated(unsafe) var task: UnsafeCurrentTask?

    init(handle: QUICStreamHandle, connection: LightweightHTTP3Connection) {
        self.handle = handle
        self.connection = connection
    }

    var eventLoop: any EventLoop { self.connection.eventLoop }

    // MARK: Consumer side, on the event loop

    /// Takes body bytes the consumer read, returning how many it took.
    func receivedBody(_ bytes: borrowing RawSpan) -> Int {
        self.state.withLock { state in
            let room = Self.maximumBufferedBodyBytes - state.body.readableBytes
            guard room > 0 else {
                state.isReadingPaused = true
                return 0
            }
            let taken = min(room, bytes.byteCount)
            bytes.extracting(0..<taken).withUnsafeBytes { _ = unsafe state.body.writeBytes($0) }
            return taken
        }
    }

    func receivedEnd(trailers: HTTPFields?) {
        self.state.withLock { state in
            state.receivedEnd = true
            state.trailers = trailers
        }
    }

    func readFailed(_ error: any Error) {
        self.state.withLock { state in
            if state.readError == nil {
                state.readError = error
            }
        }
    }

    /// Wakes the handler if it's waiting for the request.
    func wakeReader() {
        let waiter = self.state.withLock { $0.readWaiter.take() }
        waiter?.resume()
    }

    func streamClosed(error: (any Error)?) {
        var cancelTask = false
        let waiter = self.state.withLock { state in
            state.isClosed = true
            if !state.receivedEnd && state.readError == nil {
                state.readError = error ?? ChannelError.eof
            }
            // The client went away before it got the whole response: cancel the handler, like the channel-based
            // path does.
            cancelTask = !state.finishedWriting && state.hasTask
            if cancelTask {
                state.isCancellingTask = true
            }
            return state.readWaiter.take()
        }
        waiter?.resume()

        if cancelTask {
            // Outside of the lock: cancellation handlers run synchronously, and may come back here. The task can't
            // end before `isCancellingTask` is cleared, and doesn't touch `task` until then.
            unsafe self.task?.cancel()
            let cancellationWaiter = self.state.withLock { state in
                state.isCancellingTask = false
                return state.cancellationWaiter.take()
            }
            cancellationWaiter?.resume()
        }
    }

    // MARK: Handler side, anywhere

    /// Called by the handler's task, before it runs the handler.
    func attach(task: UnsafeCurrentTask?) {
        let isClosed = self.state.withLock { state in
            if state.isClosed {
                return !state.finishedWriting
            }
            unsafe self.task = unsafe task
            state.hasTask = true
            return false
        }
        if isClosed {
            // The client went away before the handler started.
            unsafe task?.cancel()
        }
    }

    /// Called by the handler's task once the handler returned: a response it didn't finish is cancelled.
    func handlerReturned() async {
        let (mustWait, cancelStream) = self.state.withLock { state in
            let cancelStream = !state.finishedWriting
            if cancelStream {
                state.finishedWriting = true
                state.pending = PendingWrites()
            }
            // While the event loop cancels the task, it uses `task`: it's cleared once it's done.
            if !state.isCancellingTask {
                state.hasTask = false
                unsafe self.task = nil
            }
            return (state.isCancellingTask, cancelStream)
        }

        if mustWait {
            // The event loop is cancelling the task: it can't end before it's done.
            await withContinuation(of: Void.self) { continuation in
                var continuation = Optional(continuation)
                self.state.withLock { state in
                    if state.isCancellingTask {
                        state.cancellationWaiter = continuation.take()
                    }
                }
                // Already done.
                continuation?.resume()
            }
            self.state.withLock { state in
                state.hasTask = false
                unsafe self.task = nil
            }
        }

        if cancelStream {
            if self.eventLoop.inEventLoop {
                self.cancelStreamOnEventLoop()
            } else {
                self.eventLoop.execute {
                    self.cancelStreamOnEventLoop()
                }
            }
        }
    }

    /// The next part of the request body: a `.body` or the `.end`. `nil` once the end was delivered.
    func read() async throws -> HTTPRequestPart? {
        enum ReadAction {
            case body(ByteBuffer, resumeReading: Bool)
            case end(HTTPFields?)
            case delivered
            case fail(any Error)
            case wait(FlushAction)
        }

        while true {
            let inEventLoop = self.eventLoop.inEventLoop
            let action = self.state.withLock { state -> ReadAction in
                if state.body.readableBytes > 0 {
                    let body = state.body
                    state.body = ByteBuffer()
                    let resumeReading = state.isReadingPaused
                    state.isReadingPaused = false
                    return .body(body, resumeReading: resumeReading)
                }
                if state.receivedEnd {
                    if state.deliveredEnd {
                        return .delivered
                    }
                    state.deliveredEnd = true
                    return .end(state.trailers)
                }
                if let error = state.readError {
                    return .fail(error)
                }
                // Send whatever the handler has written before waiting for the client.
                return .wait(Self.flushAction(&state, flush: .now, inEventLoop: inEventLoop))
            }

            switch action {
            case .body(let body, let resumeReading):
                if resumeReading {
                    self.resumeReading()
                }
                return .body(body)
            case .end(let trailers):
                return .end(trailers)
            case .delivered:
                return nil
            case .fail(let error):
                throw error
            case .wait(let flushAction):
                try self.perform(flushAction)
                await withContinuation(of: Void.self) { continuation in
                    var continuation = Optional(continuation)
                    self.state.withLock { state in
                        if !state.hasReadableEvent {
                            state.readWaiter = continuation.take()
                        }
                    }
                    // Readable already.
                    continuation?.resume()
                }
            }
        }
    }

    private func resumeReading() {
        if self.eventLoop.inEventLoop {
            self.resumeReadingOnEventLoop()
        } else {
            self.eventLoop.execute {
                self.resumeReadingOnEventLoop()
            }
        }
    }

    func sendInformational(_ response: HTTPResponse) throws {
        try self.enqueue(flush: .now) { pending in
            pending.informational.append(response)
        }
    }

    func sendHead(_ response: HTTPResponse) throws {
        // Held back until there's more to send, so a whole response goes out together.
        try self.enqueue(flush: .later) { pending in
            pending.head = response
        }
    }

    func write(_ body: ByteBuffer) throws {
        guard body.readableBytes > 0 else {
            try self.enqueue(flush: .later) { _ in }
            return
        }
        // A handler which writes and finishes without suspending is flushed by `finish`, before the flush runs.
        try self.enqueue(flush: .soon) { pending in
            pending.body.append(body)
            pending.bodyBytes += body.readableBytes
        }
    }

    /// Sends the end of the response, after `body` if it isn't `nil`.
    func finish(body: ByteBuffer? = nil, trailers: HTTPFields?) throws {
        try self.enqueue(flush: .now) { pending in
            if let body, body.readableBytes > 0 {
                pending.body.append(body)
                pending.bodyBytes += body.readableBytes
            }
            pending.end = true
            pending.trailers = trailers
        }
    }

    /// Sends a whole response.
    func sendResponse(_ response: HTTPResponse, body: ByteBuffer?, trailers: HTTPFields?) throws {
        try self.enqueue(flush: .now) { pending in
            pending.head = response
            if let body, body.readableBytes > 0 {
                pending.body.append(body)
                pending.bodyBytes += body.readableBytes
            }
            pending.end = true
            pending.trailers = trailers
        }
    }

    /// Resets the stream and asks the client to stop sending.
    func abort(resetCode: QUICApplicationErrorCode, stopSendingCode: QUICApplicationErrorCode) {
        self.state.withLock { state in
            state.finishedWriting = true
            state.pending = PendingWrites()
        }
        if self.eventLoop.inEventLoop {
            self.resetOnEventLoop(resetCode: resetCode, stopSendingCode: stopSendingCode)
        } else {
            self.eventLoop.execute {
                self.resetOnEventLoop(resetCode: resetCode, stopSendingCode: stopSendingCode)
            }
        }
    }

    /// Adds to what's waiting to be sent, and sends it as `flush` says.
    private func enqueue(flush: Flush, _ update: (inout PendingWrites) -> Void) throws {
        let inEventLoop = self.eventLoop.inEventLoop
        let action = try self.state.withLock { state throws -> FlushAction in
            if let error = state.writeError {
                throw error
            }
            // Also once the response was finished, aborted or cancelled: nothing more goes out then.
            if state.isClosed || state.finishedWriting {
                throw ChannelError.ioOnClosedChannel
            }
            update(&state.pending)
            if state.pending.end {
                state.finishedWriting = true
            }
            let effectiveFlush = state.pending.bodyBytes >= Self.flushThreshold ? .now : flush
            return Self.flushAction(&state, flush: effectiveFlush, inEventLoop: inEventLoop)
        }
        try self.perform(action)
    }

    /// What to do to send the pending writes as `flush` says. Off the event loop, they're always sent after a hop,
    /// which picks up whatever was written in the meantime.
    private static func flushAction(_ state: inout State, flush: Flush, inEventLoop: Bool) -> FlushAction {
        if state.pending.isEmpty || flush == .later {
            return .none
        }
        if inEventLoop && flush == .now {
            return .flushNow
        }
        if state.isFlushScheduled {
            return .none
        }
        state.isFlushScheduled = true
        return .scheduleFlush
    }

    private func perform(_ action: FlushAction) throws {
        switch action {
        case .none:
            ()
        case .flushNow:
            try self.flushOnEventLoop()
        case .scheduleFlush:
            self.eventLoop.execute {
                // Failures are thrown by the handler's next write.
                try? self.flushOnEventLoop(isScheduled: true)
            }
        }
    }

    // MARK: On the event loop

    /// Sends everything written so far, in one go.
    private func flushOnEventLoop(isScheduled: Bool = false) throws {
        let pending = self.state.withLock { state in
            if isScheduled {
                state.isFlushScheduled = false
            }
            let pending = state.pending
            state.pending = PendingWrites()
            return pending
        }
        guard !pending.isEmpty else { return }

        do {
            let sent: Void? = try self.connection.http3Connection.value.withRequest(self.handle) { request, stream in
                for informational in pending.informational {
                    try request.writeResponseHead(informational, to: &stream)
                }
                if let head = pending.head {
                    try request.writeResponseHead(head, to: &stream)
                }
                for body in pending.body {
                    try request.writeBody(body, to: &stream)
                }
                if pending.end {
                    try request.writeEnd(trailers: pending.trailers, to: &stream)
                }
            }
            if sent == nil {
                throw ChannelError.ioOnClosedChannel
            }
        } catch {
            self.state.withLock { state in
                if state.writeError == nil {
                    state.writeError = error
                }
            }
            throw error
        }
    }

    private func resumeReadingOnEventLoop() {
        _ = try? self.connection.http3Connection.value.withRequest(self.handle) { request, stream in
            request.resumeReading()
            LightweightHTTP3Consumer.readRequest(&request, stream: &stream, connection: self.connection)
        }
    }

    private func resetOnEventLoop(resetCode: QUICApplicationErrorCode, stopSendingCode: QUICApplicationErrorCode) {
        _ = try? self.connection.http3Connection.value.withRequest(self.handle) { _, stream in
            if stream.isReceiveOpen {
                stream.sendStopSending(code: stopSendingCode)
            }
            if stream.isSendOpen {
                stream.sendResetStream(code: resetCode)
            }
        }
    }

    private func cancelStreamOnEventLoop() {
        _ = try? self.connection.http3Connection.value.withRequest(self.handle) { request, stream in
            request.cancel(stream: &stream)
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
        group.addTask(
            name: "HTTP/3 (lightweight streams) over \(address) on \(eventLoop)",
            // Everything below, down to the request handlers, runs on the event loop, if it's a task executor.
            executorPreference: eventLoop as? any TaskExecutor
        ) {
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

    /// Runs each request of the connection in a child task.
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

        await stream.handlerReturned()
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
        let connections = LightweightHTTP3Queue<LightweightHTTP3Connection>()
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
            let http3Connection = HTTP3Connection<LightweightHTTP3Consumer>.server(
                quicConnection,
                settings: settings,
                logger: logger
            )
            let connection = LightweightHTTP3Connection(
                channel: quicConnection.channel,
                http3Connection: http3Connection
            )
            connections.yield(connection)
            return LightweightHTTP3Consumer(http3Connection: http3Connection, connection: connection)
        }

        try channel.pipeline.syncOperations.addHandler(quicHandler)
        return connections
    }
}
#endif  // HTTP3
