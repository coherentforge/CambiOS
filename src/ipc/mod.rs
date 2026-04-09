// Copyright (C) 2024-2026 Jason Ricca. All rights reserved.

//! Inter-Process Communication (IPC) for microkernel
//!
//! Defines message-passing primitives for communication between microkernel,
//! drivers, and services running in userspace. Designed for verification and
//! formal property proof.

pub mod capability;
pub mod interceptor;

extern crate alloc;
use alloc::boxed::Box;
use core::fmt;

/// Maximum number of IPC endpoints (matches MAX_PROCESSES)
pub const MAX_ENDPOINTS: usize = 32;

/// Message endpoint identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct EndpointId(pub u32);

/// Process/task identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ProcessId(pub u32);

// ============================================================================
// Principal — cryptographic identity primitive
// ============================================================================

/// A cryptographic identity: an Ed25519 public key.
///
/// In Phase 0, this is just 32 opaque bytes (no crypto verification yet).
/// The interface is permanent — the implementation gains real crypto in Phase 1.
///
/// Equality is based on the full 32-byte public key (constant-time is a
/// Phase 1 concern when real keys are in play).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Principal {
    pub public_key: [u8; 32],
}

impl Principal {
    /// Create a Principal from a 32-byte public key.
    pub const fn from_public_key(key: [u8; 32]) -> Self {
        Principal { public_key: key }
    }

    /// The zero Principal — used as a sentinel / "no identity" marker.
    pub const ZERO: Self = Principal { public_key: [0u8; 32] };

    /// Check if this is the zero (unset) Principal.
    pub fn is_zero(&self) -> bool {
        self.public_key == [0u8; 32]
    }
}

impl fmt::Debug for Principal {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // Show first 8 bytes hex for readability
        write!(f, "Principal(")?;
        for byte in &self.public_key[..8] {
            write!(f, "{:02x}", byte)?;
        }
        write!(f, "...)")
    }
}

impl fmt::Display for Principal {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for byte in &self.public_key[..8] {
            write!(f, "{:02x}", byte)?;
        }
        write!(f, "…")
    }
}

/// A single IPC message with verification-friendly structure.
///
/// # Invariants (for formal verification)
///
/// - `payload_len <= 256` (enforced by `set_payload()`).
/// - `sender_principal` is `None` on construction and set only by the kernel
///   in `send_message_with_capability()`. User code cannot forge this field.
/// - `from` and `to` are valid `EndpointId` values (< `MAX_ENDPOINTS`).
#[derive(Debug, Clone)]
pub struct Message {
    pub from: EndpointId,
    pub to: EndpointId,
    pub payload: [u8; 256], // Fixed-size for verification
    pub payload_len: usize,
    /// Sender's cryptographic identity, stamped by the kernel.
    ///
    /// This field is NEVER set by user code. The kernel writes it in
    /// `send_message_with_capability()` after the capability check passes.
    /// Recipients can trust this field unconditionally — it is unforgeable.
    pub sender_principal: Option<Principal>,
}

impl Message {
    /// Create a new message
    pub fn new(from: EndpointId, to: EndpointId) -> Self {
        Message {
            from,
            to,
            payload: [0u8; 256],
            payload_len: 0,
            sender_principal: None,
        }
    }

    /// Set message payload
    pub fn set_payload(&mut self, data: &[u8]) -> Result<(), IpcError> {
        if data.len() > 256 {
            return Err(IpcError::PayloadTooLarge);
        }
        self.payload[..data.len()].copy_from_slice(data);
        self.payload_len = data.len();
        Ok(())
    }

    /// Get message payload as slice
    pub fn payload(&self) -> &[u8] {
        &self.payload[..self.payload_len]
    }

    /// Verify message integrity
    pub fn verify(&self) -> Result<(), IpcError> {
        if self.payload_len > 256 {
            return Err(IpcError::InvalidPayloadLength);
        }
        Ok(())
    }
}

/// IPC system errors
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpcError {
    EndpointNotFound,
    ProcessNotFound,
    QueueFull,
    MessageDropped,
    PayloadTooLarge,
    InvalidPayloadLength,
    PermissionDenied,
    Timeout,
    InvalidOperation,
}

impl fmt::Display for IpcError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            IpcError::EndpointNotFound => write!(f, "Endpoint not found"),
            IpcError::ProcessNotFound => write!(f, "Process not found"),
            IpcError::QueueFull => write!(f, "Message queue full"),
            IpcError::MessageDropped => write!(f, "Message dropped"),
            IpcError::PayloadTooLarge => write!(f, "Payload exceeds maximum size"),
            IpcError::InvalidPayloadLength => write!(f, "Invalid payload length"),
            IpcError::PermissionDenied => write!(f, "Permission denied"),
            IpcError::Timeout => write!(f, "Operation timeout"),
            IpcError::InvalidOperation => write!(f, "Invalid IPC operation"),
        }
    }
}

/// Message queue interface for verification
pub trait MessageQueue {
    fn send(&mut self, msg: Message) -> Result<(), IpcError>;
    fn receive(&mut self) -> Result<Option<Message>, IpcError>;
    fn is_empty(&self) -> bool;
    fn is_full(&self) -> bool;
}

/// Capability-based security model for IPC
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapabilityRights {
    pub send: bool,
    pub receive: bool,
    pub delegate: bool,
}

impl CapabilityRights {
    pub const EMPTY: Self = CapabilityRights {
        send: false,
        receive: false,
        delegate: false,
    };

    pub const FULL: Self = CapabilityRights {
        send: true,
        receive: true,
        delegate: true,
    };

    pub const SEND_ONLY: Self = CapabilityRights {
        send: true,
        receive: false,
        delegate: false,
    };

    pub const RECV_ONLY: Self = CapabilityRights {
        send: false,
        receive: true,
        delegate: false,
    };
}

/// Fixed-size message queue for intra-kernel endpoints
///
/// Stores up to 16 messages per endpoint. Designed for verification
/// with predictable memory layout and bounded queue size.
///
/// Memory footprint: 32 queues × 16 messages × ~280 bytes per message ≈ 140KB
/// Heap-allocated at boot via IpcManager::new_boxed().
pub struct EndpointQueue {
    messages: [Option<Message>; 16],
    head: usize,
    tail: usize,
    count: usize,
}

impl EndpointQueue {
    /// Create an empty queue
    pub const fn new() -> Self {
        EndpointQueue {
            messages: [const { None }; 16],
            head: 0,
            tail: 0,
            count: 0,
        }
    }

    /// Add message to queue (FIFO)
    pub fn enqueue(&mut self, msg: Message) -> Result<(), IpcError> {
        if self.count >= 16 {
            return Err(IpcError::QueueFull);
        }

        self.messages[self.tail] = Some(msg);
        self.tail = (self.tail + 1) % 16;
        self.count += 1;
        Ok(())
    }

    /// Remove and return next message (FIFO)
    pub fn dequeue(&mut self) -> Option<Message> {
        if self.count == 0 {
            return None;
        }

        let msg = self.messages[self.head].take();
        self.head = (self.head + 1) % 16;
        self.count -= 1;
        msg
    }

    /// Check if queue is empty
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Check if queue is full
    pub fn is_full(&self) -> bool {
        self.count >= 16
    }
}

impl MessageQueue for EndpointQueue {
    fn send(&mut self, msg: Message) -> Result<(), IpcError> {
        self.enqueue(msg)
    }

    fn receive(&mut self) -> Result<Option<Message>, IpcError> {
        Ok(self.dequeue())
    }

    fn is_empty(&self) -> bool {
        EndpointQueue::is_empty(self)
    }

    fn is_full(&self) -> bool {
        EndpointQueue::is_full(self)
    }
}

/// IPC endpoint manager with scheduler integration
///
/// Coordinates message delivery and task blocking/waking for efficient
/// message-driven scheduling. Each endpoint has a queue for buffering messages.
///
/// ## Dual IPC Model
///
/// **Asynchronous (buffered):** Sender enqueues and continues.
/// Use for fire-and-forget notifications, interrupt delivery, logging.
/// - `send_message()` / `recv_message()`
///
/// **Synchronous (rendezvous):** Sender blocks until receiver picks up.
/// Use for request/reply patterns: driver→kernel calls, service RPCs.
/// - `sync_send()` / `sync_recv()` / `sync_reply()`
///
/// Most production microkernels (seL4, L4) use sync IPC as the primary
/// primitive because it's simpler to verify: no unbounded buffering,
/// deterministic transfer, natural backpressure. Async can be layered
/// on top via helper tasks if needed.
pub struct IpcManager {
    /// Async message queues (fire-and-forget)
    queues: [EndpointQueue; MAX_ENDPOINTS],
    /// Sync rendezvous channels (request/reply)
    sync_channels: [SyncChannel; MAX_ENDPOINTS],
    /// Zero-trust interceptor (set after boot init)
    interceptor: Option<Box<dyn interceptor::IpcInterceptor>>,
}

/// Synchronous IPC channel for a single endpoint
///
/// Implements rendezvous semantics:
/// - At most one pending message (no buffering)
/// - Sender blocks until receiver takes the message
/// - Receiver blocks until sender deposits a message
/// - Optional reply path for call/reply patterns
///
/// State machine:
/// ```text
///   Empty ──send()──► SenderWaiting ──recv()──► Empty (sender woken)
///   Empty ──recv()──► ReceiverWaiting ──send()──► Empty (receiver woken)
/// ```
///
/// For call/reply (RPC-style):
/// ```text
///   Empty ──call()──► CallerWaiting ──recv()──► ReplyPending ──reply()──► Empty
/// ```
pub struct SyncChannel {
    /// The rendezvous message slot
    message: Option<Message>,
    /// Reply message slot (for call/reply pattern)
    reply: Option<Message>,
    /// State of this channel
    state: SyncChannelState,
    /// Task ID of blocked sender (if any)
    sender_task: Option<u32>,
    /// Task ID of blocked receiver (if any)
    receiver_task: Option<u32>,
}

/// State of a synchronous IPC channel
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncChannelState {
    /// No pending operation
    Empty,
    /// Sender deposited message, waiting for receiver to pick up
    SenderWaiting,
    /// Receiver waiting for a message to arrive
    ReceiverWaiting,
    /// Caller (send+wait_reply) deposited message, waiting for reply
    CallerWaiting,
    /// Receiver picked up call message, sender awaiting reply
    ReplyPending,
}

impl SyncChannel {
    /// Create an empty sync channel
    pub const fn new() -> Self {
        SyncChannel {
            message: None,
            reply: None,
            state: SyncChannelState::Empty,
            sender_task: None,
            receiver_task: None,
        }
    }

    /// Deposit a message for sync send
    ///
    /// Returns:
    /// - `Ok(Some(receiver_task))` if a receiver was already waiting (wake it)
    /// - `Ok(None)` if no receiver waiting (sender should block)
    /// - `Err` if channel busy
    pub fn deposit_send(
        &mut self,
        msg: Message,
        sender_task_id: u32,
    ) -> Result<Option<u32>, IpcError> {
        match self.state {
            SyncChannelState::Empty => {
                // No receiver waiting — park the message, sender will block
                self.message = Some(msg);
                self.sender_task = Some(sender_task_id);
                self.state = SyncChannelState::SenderWaiting;
                Ok(None)
            }
            SyncChannelState::ReceiverWaiting => {
                // Receiver already waiting — direct transfer, wake receiver
                self.message = Some(msg);
                self.sender_task = Some(sender_task_id);
                let receiver = self.receiver_task.take();
                self.state = SyncChannelState::Empty;
                // Caller must wake both sender (immediate) and receiver
                Ok(receiver)
            }
            _ => Err(IpcError::QueueFull), // Channel busy with another operation
        }
    }

    /// Deposit a message for sync call (send + expect reply)
    ///
    /// Like deposit_send but caller will block waiting for reply.
    pub fn deposit_call(
        &mut self,
        msg: Message,
        caller_task_id: u32,
    ) -> Result<Option<u32>, IpcError> {
        match self.state {
            SyncChannelState::Empty => {
                self.message = Some(msg);
                self.sender_task = Some(caller_task_id);
                self.state = SyncChannelState::CallerWaiting;
                Ok(None)
            }
            SyncChannelState::ReceiverWaiting => {
                self.message = Some(msg);
                self.sender_task = Some(caller_task_id);
                let receiver = self.receiver_task.take();
                self.state = SyncChannelState::ReplyPending;
                Ok(receiver)
            }
            _ => Err(IpcError::QueueFull),
        }
    }

    /// Pick up a message (receiver side)
    ///
    /// Returns:
    /// - `Ok(Some((msg, sender_task)))` if sender was waiting (wake it unless call)
    /// - `Ok(None)` if no message available (receiver should block)
    /// - `Err` on invalid state
    pub fn pickup_recv(
        &mut self,
        receiver_task_id: u32,
    ) -> Result<Option<(Message, Option<u32>)>, IpcError> {
        match self.state {
            SyncChannelState::SenderWaiting => {
                // Sender waiting — take message, wake sender
                let msg = self.message.take().ok_or(IpcError::EndpointNotFound)?;
                let sender = self.sender_task.take();
                self.state = SyncChannelState::Empty;
                Ok(Some((msg, sender))) // Caller must wake sender
            }
            SyncChannelState::CallerWaiting => {
                // Caller waiting for reply — take message, transition to ReplyPending
                let msg = self.message.take().ok_or(IpcError::EndpointNotFound)?;
                // Don't wake sender yet — they're waiting for reply
                self.state = SyncChannelState::ReplyPending;
                Ok(Some((msg, None))) // Don't wake caller, they await reply
            }
            SyncChannelState::Empty => {
                // No message available — receiver should block
                self.receiver_task = Some(receiver_task_id);
                self.state = SyncChannelState::ReceiverWaiting;
                Ok(None)
            }
            _ => Err(IpcError::InvalidPayloadLength), // Reuse error; channel in unexpected state
        }
    }

    /// Send a reply (completing a call/reply cycle)
    ///
    /// Returns the caller's task ID so it can be woken.
    pub fn deposit_reply(&mut self, reply: Message) -> Result<u32, IpcError> {
        match self.state {
            SyncChannelState::ReplyPending => {
                let caller = self.sender_task.take().ok_or(IpcError::ProcessNotFound)?;
                self.reply = Some(reply);
                self.state = SyncChannelState::Empty;
                Ok(caller) // Caller must wake the caller task
            }
            _ => Err(IpcError::InvalidOperation),
        }
    }

    /// Take the reply message (caller side, after being woken)
    pub fn take_reply(&mut self) -> Option<Message> {
        self.reply.take()
    }

    /// Get channel state
    pub fn state(&self) -> SyncChannelState {
        self.state
    }
}

impl IpcManager {
    /// Create a new IPC manager
    pub const fn new() -> Self {
        const EMPTY_QUEUE: EndpointQueue = EndpointQueue::new();
        const EMPTY_CHANNEL: SyncChannel = SyncChannel::new();
        IpcManager {
            queues: [EMPTY_QUEUE; MAX_ENDPOINTS],
            sync_channels: [EMPTY_CHANNEL; MAX_ENDPOINTS],
            interceptor: None,
        }
    }

    /// Create a new IPC manager directly on the heap.
    /// Avoids stack overflow from the ~163KB struct.
    ///
    /// Returns `None` if heap allocation fails.
    pub fn new_boxed() -> Option<Box<Self>> {
        use alloc::alloc::{alloc_zeroed, Layout};
        let layout = Layout::new::<Self>();
        // SAFETY: layout is non-zero-sized (IpcManager contains arrays).
        let ptr = unsafe { alloc_zeroed(layout) as *mut Self };
        if ptr.is_null() {
            return None;
        }
        // SAFETY: All array fields are valid when zero-initialized:
        // - Option<Message>::None = discriminant 0 = zeroed (Message.sender_principal
        //   is only relevant inside Some(Message), which is constructed via enqueue)
        // - usize head/tail/count = 0 = zeroed
        // - SyncChannelState::Empty = first variant = discriminant 0
        // - Option<u32>::None = zeroed
        // Write the interceptor field explicitly (fat pointer — don't rely on zeroed).
        unsafe {
            core::ptr::addr_of_mut!((*ptr).interceptor).write(None);
            Some(Box::from_raw(ptr))
        }
    }

    /// Install a zero-trust interceptor for IPC policy enforcement.
    ///
    /// Called once during boot after IpcManager is allocated.
    pub fn set_interceptor(&mut self, interceptor: Box<dyn interceptor::IpcInterceptor>) {
        self.interceptor = Some(interceptor);
    }

    /// Send a message to an endpoint
    ///
    /// Places message in endpoint's queue. Caller is responsible for waking
    /// any blocked receiver (see `wake_receiver_for_endpoint`).
    pub fn send_message(&mut self, endpoint: EndpointId, msg: Message) -> Result<(), IpcError> {
        if endpoint.0 >= MAX_ENDPOINTS as u32 {
            return Err(IpcError::EndpointNotFound);
        }

        self.queues[endpoint.0 as usize].enqueue(msg)
    }

    /// Receive a message from an endpoint
    ///
    /// Returns Some(msg) if available in queue, None if empty or endpoint invalid.
    /// If caller receives None, they should block via scheduler.
    /// Once woken (message sender queued a message and called wake),
    /// caller should retry this function to get the message.
    pub fn recv_message(&mut self, endpoint: EndpointId) -> Option<Message> {
        if endpoint.0 >= MAX_ENDPOINTS as u32 {
            return None;
        }

        self.queues[endpoint.0 as usize].dequeue()
    }

    /// Check if endpoint has pending messages
    pub fn has_message(&self, endpoint: EndpointId) -> bool {
        if endpoint.0 >= MAX_ENDPOINTS as u32 {
            return false;
        }
        !self.queues[endpoint.0 as usize].is_empty()
    }

    /// Get the queue for an endpoint (for testing/inspection)
    pub fn get_queue(&self, endpoint: EndpointId) -> Option<&EndpointQueue> {
        if endpoint.0 >= MAX_ENDPOINTS as u32 {
            return None;
        }
        Some(&self.queues[endpoint.0 as usize])
    }

    /// Send a message with capability enforcement and interceptor check.
    ///
    /// Pipeline: capability check → stamp sender_principal → interceptor check → enqueue.
    ///
    /// The kernel stamps `msg.sender_principal` from the sender's bound Principal
    /// in the CapabilityManager. This is the sole code path that sets
    /// sender_principal — user code cannot forge it.
    pub fn send_message_with_capability(
        &mut self,
        from_process: ProcessId,
        endpoint: EndpointId,
        mut msg: Message,
        cap_mgr: &capability::CapabilityManager,
    ) -> Result<(), IpcError> {
        // Layer 1: Capability check
        cap_mgr
            .verify_access(from_process, endpoint, CapabilityRights::SEND_ONLY)
            .map_err(|_| IpcError::PermissionDenied)?;

        // Stamp sender identity (unforgeable — kernel sets this, never user code)
        msg.sender_principal = cap_mgr.get_principal(from_process).ok();

        // Layer 2: Interceptor check (defense-in-depth)
        if let Some(ref interceptor) = self.interceptor {
            if let interceptor::InterceptDecision::Deny(_reason) =
                interceptor.on_send(from_process, endpoint, &msg)
            {
                return Err(IpcError::PermissionDenied);
            }
        }

        // Perform the send
        self.send_message(endpoint, msg)
    }

    /// Receive a message with capability enforcement and interceptor check.
    ///
    /// Pipeline: capability check → interceptor check → dequeue.
    pub fn recv_message_with_capability(
        &mut self,
        recv_process: ProcessId,
        endpoint: EndpointId,
        cap_mgr: &capability::CapabilityManager,
    ) -> Result<Option<Message>, IpcError> {
        // Layer 1: Capability check
        cap_mgr
            .verify_access(recv_process, endpoint, CapabilityRights::RECV_ONLY)
            .map_err(|_| IpcError::PermissionDenied)?;

        // Layer 2: Interceptor check (defense-in-depth)
        if let Some(ref interceptor) = self.interceptor {
            if let interceptor::InterceptDecision::Deny(_reason) =
                interceptor.on_recv(recv_process, endpoint)
            {
                return Err(IpcError::PermissionDenied);
            }
        }

        Ok(self.recv_message(endpoint))
    }

    // ========================================================================
    // Synchronous (rendezvous) IPC
    // ========================================================================

    /// Synchronous send: deposit message, sender blocks until receiver picks up
    ///
    /// Returns:
    /// - `Ok(SyncSendResult::ReceiverWoken(task_id))`: Receiver was already waiting;
    ///    wake it. Sender does NOT block.
    /// - `Ok(SyncSendResult::SenderMustBlock)`: No receiver waiting;
    ///    caller must block sender as `SyncSendWait(endpoint)`.
    /// - `Err`: Channel busy or invalid endpoint.
    pub fn sync_send(
        &mut self,
        endpoint: EndpointId,
        msg: Message,
        sender_task_id: u32,
    ) -> Result<SyncSendResult, IpcError> {
        if endpoint.0 >= MAX_ENDPOINTS as u32 {
            return Err(IpcError::EndpointNotFound);
        }

        let channel = &mut self.sync_channels[endpoint.0 as usize];
        match channel.deposit_send(msg, sender_task_id)? {
            Some(receiver_task) => Ok(SyncSendResult::ReceiverWoken(receiver_task)),
            None => Ok(SyncSendResult::SenderMustBlock),
        }
    }

    /// Synchronous receive: pick up message or block until one arrives
    ///
    /// Returns:
    /// - `Ok(SyncRecvResult::Message(msg, wake_sender))`: Got message;
    ///    if `wake_sender` is Some, wake that task (it was blocked on send).
    /// - `Ok(SyncRecvResult::ReceiverMustBlock)`: No message available;
    ///    caller must block receiver as `SyncRecvWait(endpoint)`.
    /// - `Err`: Invalid state or endpoint.
    pub fn sync_recv(
        &mut self,
        endpoint: EndpointId,
        receiver_task_id: u32,
    ) -> Result<SyncRecvResult, IpcError> {
        if endpoint.0 >= MAX_ENDPOINTS as u32 {
            return Err(IpcError::EndpointNotFound);
        }

        let channel = &mut self.sync_channels[endpoint.0 as usize];
        match channel.pickup_recv(receiver_task_id)? {
            Some((msg, wake_sender)) => Ok(SyncRecvResult::Message(msg, wake_sender)),
            None => Ok(SyncRecvResult::ReceiverMustBlock),
        }
    }

    /// Synchronous call: send message + block until reply arrives
    ///
    /// Used for RPC-style request/reply: driver sends request, blocks until
    /// the service processes it and sends a reply back.
    ///
    /// Returns:
    /// - `Ok(SyncCallResult::ReceiverWoken(task_id))`: Receiver was waiting;
    ///    wake it. Caller blocks as `SyncReplyWait(endpoint)`.
    /// - `Ok(SyncCallResult::CallerMustBlock)`: No receiver yet;
    ///    caller blocks as `SyncReplyWait(endpoint)`.
    pub fn sync_call(
        &mut self,
        endpoint: EndpointId,
        msg: Message,
        caller_task_id: u32,
    ) -> Result<SyncCallResult, IpcError> {
        if endpoint.0 >= MAX_ENDPOINTS as u32 {
            return Err(IpcError::EndpointNotFound);
        }

        let channel = &mut self.sync_channels[endpoint.0 as usize];
        match channel.deposit_call(msg, caller_task_id)? {
            Some(receiver_task) => Ok(SyncCallResult::ReceiverWoken(receiver_task)),
            None => Ok(SyncCallResult::CallerMustBlock),
        }
    }

    /// Synchronous reply: complete a call/reply cycle
    ///
    /// Returns the caller's task ID so it can be woken to pick up the reply.
    pub fn sync_reply(
        &mut self,
        endpoint: EndpointId,
        reply: Message,
    ) -> Result<u32, IpcError> {
        if endpoint.0 >= MAX_ENDPOINTS as u32 {
            return Err(IpcError::EndpointNotFound);
        }

        self.sync_channels[endpoint.0 as usize].deposit_reply(reply)
    }

    /// Take the reply message after being woken from a sync_call
    pub fn take_reply(&mut self, endpoint: EndpointId) -> Option<Message> {
        if endpoint.0 >= MAX_ENDPOINTS as u32 {
            return None;
        }
        self.sync_channels[endpoint.0 as usize].take_reply()
    }

    /// Get sync channel state (for debugging/verification)
    pub fn sync_channel_state(&self, endpoint: EndpointId) -> Option<SyncChannelState> {
        if endpoint.0 >= MAX_ENDPOINTS as u32 {
            return None;
        }
        Some(self.sync_channels[endpoint.0 as usize].state())
    }

    /// Get a reference to the installed interceptor (if any).
    pub fn interceptor(&self) -> Option<&dyn interceptor::IpcInterceptor> {
        self.interceptor.as_deref()
    }
}

/// Result of a synchronous send operation
#[derive(Debug)]
pub enum SyncSendResult {
    /// Receiver was already waiting — wake this task ID. Sender continues.
    ReceiverWoken(u32),
    /// No receiver — caller must block sender.
    SenderMustBlock,
}

/// Result of a synchronous receive operation
#[derive(Debug)]
pub enum SyncRecvResult {
    /// Got a message. Option<u32> = sender task to wake (None if call/reply).
    Message(Message, Option<u32>),
    /// No message available — caller must block receiver.
    ReceiverMustBlock,
}

/// Result of a synchronous call operation
#[derive(Debug)]
pub enum SyncCallResult {
    /// Receiver was already waiting — wake it. Caller blocks for reply.
    ReceiverWoken(u32),
    /// No receiver — caller blocks until receiver + reply.
    CallerMustBlock,
}

// ============================================================================
// Per-endpoint sharded IPC — eliminates global IPC_MANAGER serialization
// ============================================================================

use crate::Spinlock;

/// Per-endpoint IPC shard: one queue + one sync channel, independently locked.
///
/// Each endpoint's async queue and sync channel are protected by a single
/// Spinlock per shard. Two CPUs communicating on different endpoints never
/// contend on the same lock.
pub struct EndpointShard {
    pub queue: EndpointQueue,
    pub sync_channel: SyncChannel,
}

impl EndpointShard {
    pub const fn new() -> Self {
        EndpointShard {
            queue: EndpointQueue::new(),
            sync_channel: SyncChannel::new(),
        }
    }
}

/// Sharded IPC manager — per-endpoint locking eliminates global serialization.
///
/// Instead of one global lock for all 32 endpoints, each endpoint gets its
/// own Spinlock. CPUs communicating on different endpoints never contend.
///
/// The interceptor is shared (read-only after boot), so it's stored separately
/// and accessed without per-endpoint locking.
pub struct ShardedIpcManager {
    /// Per-endpoint shards, each independently locked.
    pub shards: [Spinlock<EndpointShard>; MAX_ENDPOINTS],
    /// Zero-trust interceptor (set once at boot, read-only thereafter).
    /// Protected by its own lock since it's rarely accessed and never mutated
    /// after boot.
    interceptor: Spinlock<Option<Box<dyn interceptor::IpcInterceptor>>>,
}

impl ShardedIpcManager {
    /// Create a new sharded IPC manager.
    pub const fn new() -> Self {
        ShardedIpcManager {
            shards: [const { Spinlock::new(EndpointShard::new()) }; MAX_ENDPOINTS],
            interceptor: Spinlock::new(None),
        }
    }

    /// Install a zero-trust interceptor (called once during boot).
    pub fn set_interceptor(&self, i: Box<dyn interceptor::IpcInterceptor>) {
        *self.interceptor.lock() = Some(i);
    }

    /// Send a message to an endpoint (async).
    pub fn send_message(&self, endpoint: EndpointId, msg: Message) -> Result<(), IpcError> {
        if endpoint.0 as usize >= MAX_ENDPOINTS {
            return Err(IpcError::EndpointNotFound);
        }
        self.shards[endpoint.0 as usize].lock().queue.enqueue(msg)
    }

    /// Receive a message from an endpoint (async).
    pub fn recv_message(&self, endpoint: EndpointId) -> Option<Message> {
        if endpoint.0 as usize >= MAX_ENDPOINTS {
            return None;
        }
        self.shards[endpoint.0 as usize].lock().queue.dequeue()
    }

    /// Check if endpoint has pending messages.
    pub fn has_message(&self, endpoint: EndpointId) -> bool {
        if endpoint.0 as usize >= MAX_ENDPOINTS {
            return false;
        }
        !self.shards[endpoint.0 as usize].lock().queue.is_empty()
    }

    /// Synchronous send on a specific endpoint.
    pub fn sync_send(
        &self,
        endpoint: EndpointId,
        msg: Message,
        sender_task_id: u32,
    ) -> Result<SyncSendResult, IpcError> {
        if endpoint.0 as usize >= MAX_ENDPOINTS {
            return Err(IpcError::EndpointNotFound);
        }
        let mut shard = self.shards[endpoint.0 as usize].lock();
        match shard.sync_channel.deposit_send(msg, sender_task_id)? {
            Some(receiver_task) => Ok(SyncSendResult::ReceiverWoken(receiver_task)),
            None => Ok(SyncSendResult::SenderMustBlock),
        }
    }

    /// Synchronous receive on a specific endpoint.
    pub fn sync_recv(
        &self,
        endpoint: EndpointId,
        receiver_task_id: u32,
    ) -> Result<SyncRecvResult, IpcError> {
        if endpoint.0 as usize >= MAX_ENDPOINTS {
            return Err(IpcError::EndpointNotFound);
        }
        let mut shard = self.shards[endpoint.0 as usize].lock();
        match shard.sync_channel.pickup_recv(receiver_task_id)? {
            Some((msg, wake_sender)) => Ok(SyncRecvResult::Message(msg, wake_sender)),
            None => Ok(SyncRecvResult::ReceiverMustBlock),
        }
    }

    /// Synchronous call on a specific endpoint.
    pub fn sync_call(
        &self,
        endpoint: EndpointId,
        msg: Message,
        caller_task_id: u32,
    ) -> Result<SyncCallResult, IpcError> {
        if endpoint.0 as usize >= MAX_ENDPOINTS {
            return Err(IpcError::EndpointNotFound);
        }
        let mut shard = self.shards[endpoint.0 as usize].lock();
        match shard.sync_channel.deposit_call(msg, caller_task_id)? {
            Some(receiver_task) => Ok(SyncCallResult::ReceiverWoken(receiver_task)),
            None => Ok(SyncCallResult::CallerMustBlock),
        }
    }

    /// Synchronous reply on a specific endpoint.
    pub fn sync_reply(
        &self,
        endpoint: EndpointId,
        reply: Message,
    ) -> Result<u32, IpcError> {
        if endpoint.0 as usize >= MAX_ENDPOINTS {
            return Err(IpcError::EndpointNotFound);
        }
        self.shards[endpoint.0 as usize].lock().sync_channel.deposit_reply(reply)
    }

    /// Take reply message after being woken from sync_call.
    pub fn take_reply(&self, endpoint: EndpointId) -> Option<Message> {
        if endpoint.0 as usize >= MAX_ENDPOINTS {
            return None;
        }
        self.shards[endpoint.0 as usize].lock().sync_channel.take_reply()
    }
}

// SAFETY: ShardedIpcManager contains Spinlocks (which are Send+Sync) and
// a trait object behind a Spinlock. All fields are safe to share across threads.
unsafe impl Send for ShardedIpcManager {}
unsafe impl Sync for ShardedIpcManager {}

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // Async IPC tests
    // ========================================================================

    #[test]
    fn test_endpoint_queue_basic() {
        let mut queue = EndpointQueue::new();
        assert!(queue.is_empty());

        let msg = Message::new(EndpointId(0), EndpointId(1));
        queue.enqueue(msg).unwrap();
        assert!(!queue.is_empty());

        let received = queue.dequeue().unwrap();
        assert_eq!(received.from, EndpointId(0));
        assert_eq!(received.to, EndpointId(1));
        assert!(queue.is_empty());

    }

    #[test]
    fn test_endpoint_queue_full() {
        let mut queue = EndpointQueue::new();
        for i in 0..16 {
            let msg = Message::new(EndpointId(i), EndpointId(0));
            queue.enqueue(msg).unwrap();
        }
        assert!(queue.is_full());

        let msg = Message::new(EndpointId(99), EndpointId(0));
        assert_eq!(queue.enqueue(msg).unwrap_err(), IpcError::QueueFull);
    }

    #[test]
    fn test_ipc_manager_send_recv() {
        let mut mgr = IpcManager::new();
        let endpoint = EndpointId(5);

        let msg = Message::new(EndpointId(0), endpoint);
        mgr.send_message(endpoint, msg).unwrap();

        assert!(mgr.has_message(endpoint));
        let received = mgr.recv_message(endpoint).unwrap();
        assert_eq!(received.to, endpoint);
        assert!(!mgr.has_message(endpoint));
    }

    // ========================================================================
    // Sync IPC tests
    // ========================================================================

    #[test]
    fn test_sync_channel_send_then_recv() {
        // Scenario: sender deposits first, then receiver picks up
        let mut channel = SyncChannel::new();
        assert_eq!(channel.state(), SyncChannelState::Empty);

        let msg = Message::new(EndpointId(0), EndpointId(1));
        let result = channel.deposit_send(msg, 10).unwrap();
        assert!(result.is_none()); // No receiver waiting
        assert_eq!(channel.state(), SyncChannelState::SenderWaiting);

        // Receiver picks up
        let result = channel.pickup_recv(20).unwrap().unwrap();
        let (received_msg, wake_sender) = result;
        assert_eq!(received_msg.from, EndpointId(0));
        assert_eq!(wake_sender, Some(10)); // Sender should be woken
        assert_eq!(channel.state(), SyncChannelState::Empty);
    }

    #[test]
    fn test_sync_channel_recv_then_send() {
        // Scenario: receiver waits first, then sender deposits
        let mut channel = SyncChannel::new();

        // Receiver requests (no message yet)
        let result = channel.pickup_recv(20).unwrap();
        assert!(result.is_none()); // Must block
        assert_eq!(channel.state(), SyncChannelState::ReceiverWaiting);

        // Sender deposits while receiver is waiting
        let msg = Message::new(EndpointId(0), EndpointId(1));
        let result = channel.deposit_send(msg, 10).unwrap();
        assert_eq!(result, Some(20)); // Receiver task 20 should be woken
        assert_eq!(channel.state(), SyncChannelState::Empty);
    }

    #[test]
    fn test_sync_call_reply_cycle() {
        // Full RPC cycle: call → recv → reply → take_reply
        let mut channel = SyncChannel::new();

        // Step 1: Caller sends request
        let request = Message::new(EndpointId(0), EndpointId(1));
        let result = channel.deposit_call(request, 10).unwrap();
        assert!(result.is_none()); // No receiver, caller must block
        assert_eq!(channel.state(), SyncChannelState::CallerWaiting);

        // Step 2: Receiver picks up request
        let result = channel.pickup_recv(20).unwrap().unwrap();
        let (request_msg, wake_sender) = result;
        assert_eq!(request_msg.from, EndpointId(0));
        assert!(wake_sender.is_none()); // Don't wake caller yet (waiting for reply)
        assert_eq!(channel.state(), SyncChannelState::ReplyPending);

        // Step 3: Receiver sends reply
        let reply = Message::new(EndpointId(1), EndpointId(0));
        let caller_task = channel.deposit_reply(reply).unwrap();
        assert_eq!(caller_task, 10); // Caller should be woken
        assert_eq!(channel.state(), SyncChannelState::Empty);

        // Step 4: Caller picks up reply
        let reply_msg = channel.take_reply().unwrap();
        assert_eq!(reply_msg.from, EndpointId(1));
    }

    #[test]
    fn test_sync_call_with_waiting_receiver() {
        // Receiver waits first, then caller does call()
        let mut channel = SyncChannel::new();

        // Receiver waits
        let result = channel.pickup_recv(20).unwrap();
        assert!(result.is_none());
        assert_eq!(channel.state(), SyncChannelState::ReceiverWaiting);

        // Caller does call() — receiver gets woken
        let request = Message::new(EndpointId(0), EndpointId(1));
        let result = channel.deposit_call(request, 10).unwrap();
        assert_eq!(result, Some(20)); // Wake receiver
        assert_eq!(channel.state(), SyncChannelState::ReplyPending);

        // Receiver sends reply
        let reply = Message::new(EndpointId(1), EndpointId(0));
        let caller_task = channel.deposit_reply(reply).unwrap();
        assert_eq!(caller_task, 10);
    }

    #[test]
    fn test_sync_manager_send_recv() {
        let mut mgr = IpcManager::new();
        let endpoint = EndpointId(5);

        // Send (no receiver waiting)
        let msg = Message::new(EndpointId(0), endpoint);
        let result = mgr.sync_send(endpoint, msg, 10).unwrap();
        assert!(matches!(result, SyncSendResult::SenderMustBlock));

        // Receive (sender was waiting)
        let result = mgr.sync_recv(endpoint, 20).unwrap();
        match result {
            SyncRecvResult::Message(msg, wake_sender) => {
                assert_eq!(msg.from, EndpointId(0));
                assert_eq!(wake_sender, Some(10));
            }
            _ => panic!("Expected Message"),
        }
    }

    #[test]
    fn test_sync_manager_call_reply() {
        let mut mgr = IpcManager::new();
        let endpoint = EndpointId(5);

        // Call (no receiver)
        let request = Message::new(EndpointId(0), endpoint);
        let result = mgr.sync_call(endpoint, request, 10).unwrap();
        assert!(matches!(result, SyncCallResult::CallerMustBlock));

        // Service receives
        let result = mgr.sync_recv(endpoint, 20).unwrap();
        assert!(matches!(result, SyncRecvResult::Message(_, None))); // Don't wake caller

        // Service replies — wake caller
        let reply = Message::new(endpoint, EndpointId(0));
        let caller_task = mgr.sync_reply(endpoint, reply).unwrap();
        assert_eq!(caller_task, 10);

        // Caller picks up reply
        let reply_msg = mgr.take_reply(endpoint).unwrap();
        assert_eq!(reply_msg.from, endpoint);
    }

    #[test]
    fn test_sync_channel_busy_rejected() {
        let mut channel = SyncChannel::new();

        // First send
        let msg = Message::new(EndpointId(0), EndpointId(1));
        channel.deposit_send(msg, 10).unwrap();

        // Second send on busy channel — rejected
        let msg2 = Message::new(EndpointId(0), EndpointId(1));
        assert!(channel.deposit_send(msg2, 11).is_err());
    }

    // ========================================================================
    // Principal + Message identity tests
    // ========================================================================

    #[test]
    fn test_message_sender_principal_defaults_to_none() {
        let msg = Message::new(EndpointId(0), EndpointId(1));
        assert!(msg.sender_principal.is_none());
    }

    #[test]
    fn test_send_with_capability_stamps_principal() {
        use crate::ipc::capability::CapabilityManager;

        let mut mgr = IpcManager::new();
        let mut cap_mgr = CapabilityManager::new();

        let proc_id = ProcessId(0);
        let endpoint = EndpointId(5);
        let principal = Principal::from_public_key([0xAA; 32]);

        // Set up: register process, grant capability, bind Principal
        cap_mgr.register_process(proc_id).unwrap();
        cap_mgr.grant_capability(proc_id, endpoint, CapabilityRights::FULL).unwrap();
        cap_mgr.bind_principal(proc_id, principal).unwrap();

        // Send a message through the capability-checked path
        let msg = Message::new(EndpointId(0), endpoint);
        mgr.send_message_with_capability(proc_id, endpoint, msg, &cap_mgr).unwrap();

        // Verify: the received message has sender_principal stamped by kernel
        let received = mgr.recv_message(endpoint).unwrap();
        assert_eq!(received.sender_principal, Some(principal));
    }

    #[test]
    fn test_send_with_capability_no_principal_stamps_none() {
        use crate::ipc::capability::CapabilityManager;

        let mut mgr = IpcManager::new();
        let mut cap_mgr = CapabilityManager::new();

        let proc_id = ProcessId(0);
        let endpoint = EndpointId(5);

        // Register process with capability but NO Principal bound
        cap_mgr.register_process(proc_id).unwrap();
        cap_mgr.grant_capability(proc_id, endpoint, CapabilityRights::FULL).unwrap();

        let msg = Message::new(EndpointId(0), endpoint);
        mgr.send_message_with_capability(proc_id, endpoint, msg, &cap_mgr).unwrap();

        // No Principal bound → Err from get_principal → None stamped
        let received = mgr.recv_message(endpoint).unwrap();
        assert!(received.sender_principal.is_none());
    }

    #[test]
    fn test_direct_send_does_not_stamp_principal() {
        // send_message() (non-capability path) does NOT stamp sender_principal.
        // Only send_message_with_capability() does. This is by design:
        // the kernel stamps identity only through the authorized path.
        let mut mgr = IpcManager::new();
        let endpoint = EndpointId(5);

        let msg = Message::new(EndpointId(0), endpoint);
        mgr.send_message(endpoint, msg).unwrap();

        let received = mgr.recv_message(endpoint).unwrap();
        assert!(received.sender_principal.is_none());
    }
}
