// Copyright 2018 (c) rust-themis developers
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Secure Session service.
//!
//! **Secure Session** is a lightweight mechanism for securing any kind of network communication
//! (both private and public networks, including the Internet).

use std::{ptr, slice};

use libc::{c_int, c_void, size_t, ssize_t, uint8_t};

use error::{themis_status_t, Error, ErrorKind};
use utils::into_raw_parts;

#[link(name = "themis")]
extern "C" {
    fn secure_session_create(
        id_ptr: *const uint8_t,
        id_len: size_t,
        key_ptr: *const uint8_t,
        key_len: size_t,
        user_callbacks: *const secure_session_user_callbacks_t,
    ) -> *mut secure_session_t;

    fn secure_session_destroy(session_ctx: *mut secure_session_t) -> themis_status_t;

    fn secure_session_is_established(session_ctx: *const secure_session_t) -> bool;

    fn secure_session_get_remote_id(
        session_ctx: *const secure_session_t,
        id_ptr: *mut uint8_t,
        id_len: *mut size_t,
    ) -> themis_status_t;

    fn secure_session_generate_connect_request(
        session_ctx: *mut secure_session_t,
        output_ptr: *mut uint8_t,
        output_len: *mut size_t,
    ) -> themis_status_t;

    fn secure_session_wrap(
        session_ctx: *mut secure_session_t,
        message_ptr: *const uint8_t,
        message_len: size_t,
        wrapped_ptr: *mut uint8_t,
        wrapper_len: *mut size_t,
    ) -> themis_status_t;

    fn secure_session_unwrap(
        session_ctx: *mut secure_session_t,
        wrapped_ptr: *const uint8_t,
        wrapped_len: size_t,
        message_ptr: *mut uint8_t,
        message_len: *mut size_t,
    ) -> themis_status_t;

    fn secure_session_connect(session_ctx: *mut secure_session_t) -> themis_status_t;

    fn secure_session_send(
        session_ctx: *mut secure_session_t,
        message_ptr: *const uint8_t,
        message_len: size_t,
    ) -> ssize_t;

    fn secure_session_receive(
        session_ctx: *mut secure_session_t,
        message_ptr: *mut uint8_t,
        message_len: size_t,
    ) -> ssize_t;
}

#[allow(non_camel_case_types)]
type secure_session_t = c_void;

#[allow(non_camel_case_types)]
#[repr(C)]
struct secure_session_user_callbacks_t {
    send_data:
        extern "C" fn(data: *const uint8_t, length: size_t, user_data: *mut c_void) -> ssize_t,
    receive_data:
        extern "C" fn(data: *mut uint8_t, length: size_t, user_data: *mut c_void) -> ssize_t,
    state_changed: extern "C" fn(event: c_int, user_data: *mut c_void),
    get_public_key_for_id: extern "C" fn(
        id_ptr: *const uint8_t,
        id_len: size_t,
        key_ptr: *mut uint8_t,
        key_len: size_t,
        user_data: *mut c_void,
    ) -> c_int,
    user_data: *mut c_void,
}

/// Secure Session context.
pub struct SecureSession<T> {
    session_ctx: *mut secure_session_t,
    _delegate: Box<SecureSessionDelegate<T>>,
}

/// Transport delegate for Secure Session.
///
/// This is an interface you need to provide for Secure Session operation.
///
/// The only required method is [`get_public_key_for_id`]. It is required for public key
/// authentication. Other methods are optional, you can use Secure Session without them,
/// but some functionality may be unavailable.
///
/// [`get_public_key_for_id`]: trait.SecureSessionTransport.html#tymethod.get_public_key_for_id
#[allow(unused_variables)]
pub trait SecureSessionTransport {
    // TODO: consider send/receive use std::io::Error for errors (or a custom type)

    /// Send the provided data to the peer, return the number of bytes transferred.
    ///
    /// This callback will be called when Secure Session needs to send some data to its peer.
    /// The whole message is expected to be transferred so returning anything other than
    /// `Ok(data.len())` is considered an error.
    ///
    /// This method is used by the transport API ([`connect`], [`negotiate_transport`], [`send`]).
    /// You need to implement it in order to use this API.
    ///
    /// [`connect`]: struct.SecureSession.html#method.connect
    /// [`negotiate_transport`]: struct.SecureSession.html#method.negotiate_transport
    /// [`send`]: struct.SecureSession.html#method.send
    fn send_data(&mut self, data: &[u8]) -> Result<usize, ()> {
        Err(())
    }

    /// Receive some data from the peer into the provided buffer, return the number of bytes.
    ///
    /// This callback will be called when Secure Session expects to receive some data. The length
    /// of the buffer indicates the maximum amount of data expected. Put the received data into
    /// the provided buffer and return the number of bytes that you used.
    ///
    /// This method is used by the transport API ([`negotiate_transport`], [`receive`]).
    /// You need to implement it in order to use this API.
    ///
    /// [`negotiate_transport`]: struct.SecureSession.html#method.negotiate_transport
    /// [`receive`]: struct.SecureSession.html#method.receive
    fn receive_data(&mut self, data: &mut [u8]) -> Result<usize, ()> {
        Err(())
    }

    /// Notification about connection state of Secure Session.
    ///
    /// This method is truly optional and has no effect on Secure Session operation.
    fn state_changed(&mut self, state: SecureSessionState) {}

    /// Get a public key corresponding to a peer ID.
    ///
    /// Look up the key and place it into the provided buffer. Return `true` if a key has been
    /// found for the provided ID and `false` for unknown IDs.
    fn get_public_key_for_id(&mut self, id: &[u8], key: &mut [u8]) -> bool;
}

// We keep this struct in a box so that it has fixed address. Themis does *not* copy
// the callback struct into session context, it keeps a pointer to it. The callback
// structure itself also stores a `user_data` pointer to itself, so it's important
// to have this structure pinned in memory.
struct SecureSessionDelegate<T> {
    callbacks: secure_session_user_callbacks_t,
    transport: T,
}

/// State of Secure Session connection.
#[derive(PartialEq, Eq)]
pub enum SecureSessionState {
    /// Newly created sessions start in this state.
    Idle,
    /// Connection establishment in progress.
    Negotiation,
    /// Connection has been established, data exchange may commence.
    Established,
}

impl SecureSessionState {
    fn from_int(state: c_int) -> Option<Self> {
        match state {
            0 => Some(SecureSessionState::Idle),
            1 => Some(SecureSessionState::Negotiation),
            2 => Some(SecureSessionState::Established),
            _ => None,
        }
    }
}

impl<T> SecureSession<T>
where
    T: SecureSessionTransport,
{
    // TODO: introduce a builder

    /// Creates a new Secure Session.
    ///
    /// ID is an arbitrary byte sequence used to identify this peer.
    ///
    /// Secure Session supports only ECDSA keys.
    ///
    /// Returns `None` if anything is wrong with the parameters.
    pub fn with_transport<I, K>(id: I, key: K, transport: T) -> Option<Self>
    where
        I: AsRef<[u8]>,
        K: AsRef<[u8]>,
    {
        let (id_ptr, id_len) = into_raw_parts(id.as_ref());
        let (key_ptr, key_len) = into_raw_parts(key.as_ref());
        let delegate = SecureSessionDelegate::new(transport);

        let user_callbacks = delegate.user_callbacks();
        let session_ctx =
            unsafe { secure_session_create(id_ptr, id_len, key_ptr, key_len, user_callbacks) };

        if session_ctx.is_null() {
            return None;
        }

        Some(Self {
            session_ctx,
            _delegate: delegate,
        })
    }

    /// Returns `true` if this Secure Session may be used for data transfer.
    pub fn is_established(&self) -> bool {
        unsafe { secure_session_is_established(self.session_ctx) }
    }

    // TODO: abstract out the 'check-allocate-leap' pattern
    //
    // This is really common here to call a C function to get a size of the buffer, then allocate
    // memory, then call the function again to do actual work, then fix the length of the vector.
    // It would be nice to have this abstracted out so that we don't have to repeat ourselves.

    /// Returns ID of the remote peer.
    ///
    /// This method will return an error if the connection has not been established yet.
    pub fn get_remote_id(&self) -> Result<Vec<u8>, Error> {
        let mut id = Vec::new();
        let mut id_len = 0;

        unsafe {
            let status =
                secure_session_get_remote_id(self.session_ctx, ptr::null_mut(), &mut id_len);
            let error = Error::from_session_status(status);
            if error.kind() != ErrorKind::BufferTooSmall {
                return Err(error);
            }
        }

        id.reserve(id_len);

        unsafe {
            let status =
                secure_session_get_remote_id(self.session_ctx, id.as_mut_ptr(), &mut id_len);
            let error = Error::from_session_status(status);
            if error.kind() != ErrorKind::Success {
                return Err(error);
            }
            debug_assert!(id_len <= id.capacity());
            id.set_len(id_len);
        }

        Ok(id)
    }

    /// Initiates connection to the remote peer.
    ///
    /// This is the first method to call. It uses transport callbacks to send the resulting
    /// connection request to the peer. Afterwards call [`negotiate_transport`] until the
    /// connection is established. That is, until the [`state_changed`] callback of your
    /// `SecureSessionTransport` tells you that the connection is `Established`, or until
    /// [`is_established`] on this Secure Session returns `true`.
    ///
    /// This method is a part of transport API and requires [`send_data`] method of
    /// `SecureSessionTransport`.
    ///
    /// [`negotiate_transport`]: struct.SecureSession.html#method.negotiate_transport
    /// [`state_changed`]: trait.SecureSessionTransport.html#method.state_changed
    /// [`is_established`]: struct.SecureSession.html#method.is_established
    /// [`send_data`]: trait.SecureSessionTransport.html#method.send_data
    pub fn connect(&mut self) -> Result<(), Error> {
        unsafe {
            let status = secure_session_connect(self.session_ctx);
            let error = Error::from_session_status(status);
            if error.kind() != ErrorKind::Success {
                return Err(error);
            }
        }
        Ok(())
    }

    /// Initiates connection to the remote peer, returns connection message.
    ///
    /// This is the first method to call. It returns you a message that you must somehow
    /// transfer to the remote peer and give it to its [`negotiate`] method. This results in
    /// another message which must be transferred back to this Secure Session and passed to
    /// its [`negotiate`] method. Continue passing these message around until the connection
    /// is established. That is, until the [`state_changed`] callback of your
    /// `SecureSessionTransport` tells you that the connection is `Established`, or until
    /// [`is_established`] on this Secure Session returns `true`, or until [`negotiate`]
    /// returns an empty message.
    ///
    /// [`negotiate`]: struct.SecureSession.html#method.negotiate
    /// [`state_changed`]: trait.SecureSessionTransport.html#method.state_changed
    /// [`is_established`]: struct.SecureSession.html#method.is_established
    pub fn generate_connect_request(&mut self) -> Result<Vec<u8>, Error> {
        let mut output = Vec::new();
        let mut output_len = 0;

        unsafe {
            let status = secure_session_generate_connect_request(
                self.session_ctx,
                ptr::null_mut(),
                &mut output_len,
            );
            let error = Error::from_session_status(status);
            if error.kind() != ErrorKind::BufferTooSmall {
                return Err(error);
            }
        }

        output.reserve(output_len);

        unsafe {
            let status = secure_session_generate_connect_request(
                self.session_ctx,
                output.as_mut_ptr(),
                &mut output_len,
            );
            let error = Error::from_session_status(status);
            if error.kind() != ErrorKind::Success {
                return Err(error);
            }
            debug_assert!(output_len <= output.capacity());
            output.set_len(output_len);
        }

        Ok(output)
    }

    /// Wraps a message and returns it.
    ///
    /// The message can be transferred to the remote peer and unwrapped there with [`unwrap`].
    ///
    /// Wrapped message are independent and can be exchanged out of order. You can wrap multiple
    /// messages then unwrap them in any order or don't unwrap some of them at all.
    ///
    /// This method will fail if a secure connection has not been established yet.
    ///
    /// [`unwrap`]: struct.SecureSession.html#method.unwrap
    pub fn wrap<M: AsRef<[u8]>>(&mut self, message: M) -> Result<Vec<u8>, Error> {
        let (message_ptr, message_len) = into_raw_parts(message.as_ref());

        let mut wrapped = Vec::new();
        let mut wrapped_len = 0;

        unsafe {
            let status = secure_session_wrap(
                self.session_ctx,
                message_ptr,
                message_len,
                ptr::null_mut(),
                &mut wrapped_len,
            );
            let error = Error::from_session_status(status);
            if error.kind() != ErrorKind::BufferTooSmall {
                return Err(error);
            }
        }

        wrapped.reserve(wrapped_len);

        unsafe {
            let status = secure_session_wrap(
                self.session_ctx,
                message_ptr,
                message_len,
                wrapped.as_mut_ptr(),
                &mut wrapped_len,
            );
            let error = Error::from_session_status(status);
            if error.kind() != ErrorKind::Success {
                return Err(error);
            }
            debug_assert!(wrapped_len <= wrapped.capacity());
            wrapped.set_len(wrapped_len);
        }

        Ok(wrapped)
    }

    /// Unwraps a message and returns it.
    ///
    /// Unwraps a message previously [wrapped] by the remote peer.
    ///
    /// This method will fail if a secure connection has not been established yet.
    ///
    /// [wrapped]: struct.SecureSession.html#method.wrap
    pub fn unwrap<M: AsRef<[u8]>>(&mut self, wrapped: M) -> Result<Vec<u8>, Error> {
        let (wrapped_ptr, wrapped_len) = into_raw_parts(wrapped.as_ref());

        let mut message = Vec::new();
        let mut message_len = 0;

        unsafe {
            let status = secure_session_unwrap(
                self.session_ctx,
                wrapped_ptr,
                wrapped_len,
                ptr::null_mut(),
                &mut message_len,
            );
            let error = Error::from_session_status(status);
            if error.kind() != ErrorKind::BufferTooSmall {
                return Err(error);
            }
        }

        message.reserve(message_len);

        unsafe {
            let status = secure_session_unwrap(
                self.session_ctx,
                wrapped_ptr,
                wrapped_len,
                message.as_mut_ptr(),
                &mut message_len,
            );
            let error = Error::from_session_status(status);
            if error.kind() != ErrorKind::Success {
                return Err(error);
            }
            debug_assert!(message_len <= message.capacity());
            message.set_len(message_len);
        }

        Ok(message)
    }

    /// Continues connection negotiation with given message.
    ///
    /// This method performs one step of connection negotiation. The server should call this
    /// method first with a message received from client's [`generate_connect_request`].
    /// Its result is another negotiation message that should be transferred to the client.
    /// The client then calls this method on a message and forwards the resulting message
    /// to the server. If the returned message is empty then negotiation is complete and
    /// the Secure Session is ready to be used.
    ///
    /// [`negotiate`]: struct.SecureSession.html#method.negotiate
    /// [`generate_connect_request`]: struct.SecureSession.html#method.generate_connect_request
    pub fn negotiate<M: AsRef<[u8]>>(&mut self, wrapped: M) -> Result<Vec<u8>, Error> {
        let (wrapped_ptr, wrapped_len) = into_raw_parts(wrapped.as_ref());

        let mut message = Vec::new();
        let mut message_len = 0;

        unsafe {
            let status = secure_session_unwrap(
                self.session_ctx,
                wrapped_ptr,
                wrapped_len,
                ptr::null_mut(),
                &mut message_len,
            );
            let error = Error::from_session_status(status);
            if error.kind() == ErrorKind::Success {
                return Ok(message);
            }
            if error.kind() != ErrorKind::BufferTooSmall {
                return Err(error);
            }
        }

        message.reserve(message_len);

        unsafe {
            let status = secure_session_unwrap(
                self.session_ctx,
                wrapped_ptr,
                wrapped_len,
                message.as_mut_ptr(),
                &mut message_len,
            );
            let error = Error::from_session_status(status);
            if error.kind() != ErrorKind::SessionSendOutputToPeer {
                assert_ne!(error.kind(), ErrorKind::Success);
                return Err(error);
            }
            debug_assert!(message_len <= message.capacity());
            message.set_len(message_len);
        }

        Ok(message)
    }

    // TODO: make Themis improve the error reporting for send and receive
    //
    // Themis sends messages in full. Partial transfer is considered an error. In case of an
    // error the error code is returned in-band and cannot be distinguished from a successful
    // return of message length. This is the best we can do at the moment.
    //
    // Furthermore, Themis expects the send callback to send the whole message so it is kinda
    // pointless to return the amount of bytes send. The receive callback returns accurate number
    // of bytes, but I do not really like the Rust interface this implies. It could be made better.

    /// Sends a message to the remote peer.
    ///
    /// This method will fail if a secure connection has not been established yet.
    ///
    /// This method is a part of transport API and requires [`send_data`] method of
    /// `SecureSessionTransport`.
    ///
    /// [`send_data`]: trait.SecureSessionTransport.html#method.send_data
    pub fn send<M: AsRef<[u8]>>(&mut self, message: M) -> Result<(), Error> {
        let (message_ptr, message_len) = into_raw_parts(message.as_ref());

        unsafe {
            let length = secure_session_send(self.session_ctx, message_ptr, message_len);
            if length <= 21 {
                return Err(Error::from_session_status(length as themis_status_t));
            }
        }

        Ok(())
    }

    /// Receives a message from the remote peer.
    ///
    /// Maximum length of the message is specified by the parameter. The message will be truncated
    /// to this length if the peer sends something larger.
    ///
    /// This method will fail if a secure connection has not been established yet.
    ///
    /// This method is a part of transport API and requires [`receive_data`] method of
    /// `SecureSessionTransport`.
    ///
    /// [`receive_data`]: trait.SecureSessionTransport.html#method.receive_data
    pub fn receive(&mut self, max_len: usize) -> Result<Vec<u8>, Error> {
        let mut message = Vec::with_capacity(max_len);

        unsafe {
            let length =
                secure_session_receive(self.session_ctx, message.as_mut_ptr(), message.capacity());
            if length <= 21 {
                return Err(Error::from_session_status(length as themis_status_t));
            }
            debug_assert!(length as usize <= message.capacity());
            message.set_len(length as usize);
        }

        Ok(message)
    }

    /// Continues connection negotiation.
    ///
    /// This method performs one step of connection negotiation. This is the first method to call
    /// for the server, the client calls it after the initial [`connect`]. Both peers shall then
    /// repeatedly call this method until the connection is established (see [`connect`] for
    /// details).
    ///
    /// This method is a part of transport API and requires [`send_data`] and [`receive_data`]
    /// methods of `SecureSessionTransport`.
    ///
    /// [`connect`]: struct.SecureSession.html#method.connect
    /// [`send_data`]: trait.SecureSessionTransport.html#method.send_data
    /// [`receive_data`]: trait.SecureSessionTransport.html#method.receive_data
    pub fn negotiate_transport(&mut self) -> Result<(), Error> {
        unsafe {
            let result = secure_session_receive(self.session_ctx, ptr::null_mut(), 0);
            let error = Error::from_session_status(result as themis_status_t);
            if error.kind() != ErrorKind::Success {
                return Err(error);
            }
        }

        Ok(())
    }
}

impl<T> SecureSessionDelegate<T>
where
    T: SecureSessionTransport,
{
    pub fn new(transport: T) -> Box<Self> {
        let mut delegate = Box::new(Self {
            callbacks: secure_session_user_callbacks_t {
                send_data: Self::send_data,
                receive_data: Self::receive_data,
                state_changed: Self::state_changed,
                get_public_key_for_id: Self::get_public_key_for_id,
                user_data: ptr::null_mut(),
            },
            transport,
        });
        delegate.callbacks.user_data = delegate.transport_ptr();
        delegate
    }

    pub fn user_callbacks(&self) -> *const secure_session_user_callbacks_t {
        &self.callbacks
    }

    // These functions are unsafe. They should be used only for `user_data` conversion.

    fn transport_ptr(&mut self) -> *mut c_void {
        &mut self.transport as *mut T as *mut c_void
    }

    fn transport<'a>(ptr: *mut c_void) -> &'a mut T {
        unsafe { &mut *(ptr as *mut T) }
    }

    extern "C" fn send_data(
        data_ptr: *const uint8_t,
        data_len: size_t,
        user_data: *mut c_void,
    ) -> ssize_t {
        let data = byte_slice_from_ptr(data_ptr, data_len);
        let transport = Self::transport(user_data);

        transport
            .send_data(data)
            .ok()
            .and_then(as_ssize)
            .unwrap_or(-1)
    }

    extern "C" fn receive_data(
        data_ptr: *mut uint8_t,
        data_len: size_t,
        user_data: *mut c_void,
    ) -> ssize_t {
        let data = byte_slice_from_ptr_mut(data_ptr, data_len);
        let transport = Self::transport(user_data);

        transport
            .receive_data(data)
            .ok()
            .and_then(as_ssize)
            .unwrap_or(-1)
    }

    extern "C" fn state_changed(event: c_int, user_data: *mut c_void) {
        let transport = Self::transport(user_data);

        if let Some(state) = SecureSessionState::from_int(event) {
            transport.state_changed(state);
        }
    }

    extern "C" fn get_public_key_for_id(
        id_ptr: *const uint8_t,
        id_len: size_t,
        key_ptr: *mut uint8_t,
        key_len: size_t,
        user_data: *mut c_void,
    ) -> c_int {
        let id = byte_slice_from_ptr(id_ptr, id_len);
        let key = byte_slice_from_ptr_mut(key_ptr, key_len);
        let transport = Self::transport(user_data);

        if transport.get_public_key_for_id(id, key) {
            0
        } else {
            -1
        }
    }
}

#[doc(hidden)]
impl<D> Drop for SecureSession<D> {
    fn drop(&mut self) {
        unsafe {
            let status = secure_session_destroy(self.session_ctx);
            let error = Error::from_session_status(status);
            if (cfg!(debug) || cfg!(test)) && error.kind() != ErrorKind::Success {
                panic!("secure_session_destroy() failed: {}", error);
            }
        }
    }
}

fn as_ssize(n: usize) -> Option<ssize_t> {
    if n <= ssize_t::max_value() as usize {
        Some(n as ssize_t)
    } else {
        None
    }
}

// These functions are technically unsafe. You must trust the C code to give you correct pointers
// and lengths. Note that empty Rust slices must *not* be constructed from a null raw pointer,
// they should use a special value instead. This is important for some LLVM magic.

fn byte_slice_from_ptr<'a>(ptr: *const uint8_t, len: size_t) -> &'a [u8] {
    unsafe { slice::from_raw_parts(escape_null_ptr(ptr as *mut u8), len) }
}

fn byte_slice_from_ptr_mut<'a>(ptr: *mut uint8_t, len: size_t) -> &'a mut [u8] {
    unsafe { slice::from_raw_parts_mut(escape_null_ptr(ptr), len) }
}

fn escape_null_ptr<T>(ptr: *mut T) -> *mut T {
    if ptr.is_null() {
        ptr::NonNull::dangling().as_ptr()
    } else {
        ptr
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::BTreeMap;
    use std::rc::Rc;
    use std::sync::mpsc::{channel, Receiver, Sender};

    use keygen::gen_ec_key_pair;

    struct DummyTransport {
        key_map: Rc<BTreeMap<Vec<u8>, Vec<u8>>>,
    }

    impl DummyTransport {
        fn new(key_map: &Rc<BTreeMap<Vec<u8>, Vec<u8>>>) -> Self {
            Self {
                key_map: key_map.clone(),
            }
        }
    }

    impl SecureSessionTransport for DummyTransport {
        fn get_public_key_for_id(&mut self, id: &[u8], key_out: &mut [u8]) -> bool {
            if let Some(key) = self.key_map.get(id) {
                assert!(key_out.len() >= key.len());
                key_out[0..key.len()].copy_from_slice(key);
                true
            } else {
                false
            }
        }
    }

    struct ChannelTransport {
        key_map: Rc<BTreeMap<Vec<u8>, Vec<u8>>>,
        tx: Sender<Vec<u8>>,
        rx: Receiver<Vec<u8>>,
    }

    impl ChannelTransport {
        fn new(key_map: &Rc<BTreeMap<Vec<u8>, Vec<u8>>>) -> (Self, Self) {
            let (tx12, rx21) = channel();
            let (tx21, rx12) = channel();

            let transport1 = Self {
                key_map: key_map.clone(),
                tx: tx12,
                rx: rx12,
            };
            let transport2 = Self {
                key_map: key_map.clone(),
                tx: tx21,
                rx: rx21,
            };

            (transport1, transport2)
        }
    }

    impl SecureSessionTransport for ChannelTransport {
        fn send_data(&mut self, data: &[u8]) -> Result<usize, ()> {
            self.tx
                .send(data.to_vec())
                .map(|_| data.len())
                .map_err(|_| ())
        }

        fn receive_data(&mut self, data: &mut [u8]) -> Result<usize, ()> {
            let msg = self.rx.recv().map_err(|_| ())?;
            if msg.len() > data.len() {
                return Err(());
            }
            data[0..msg.len()].copy_from_slice(&msg);
            Ok(msg.len())
        }

        fn get_public_key_for_id(&mut self, id: &[u8], key_out: &mut [u8]) -> bool {
            if let Some(key) = self.key_map.get(id) {
                assert!(key_out.len() >= key.len());
                key_out[0..key.len()].copy_from_slice(key);
                true
            } else {
                false
            }
        }
    }

    #[test]
    fn no_transport() {
        // Peer credentials. Secure Session supports only ECDSA.
        // TODO: tests that confirm RSA failure
        let (private_client, public_client) = gen_ec_key_pair().unwrap();
        let (private_server, public_server) = gen_ec_key_pair().unwrap();
        let (name_client, name_server) = ("client", "server");

        // Shared storage of public peer credentials. These should be communicated between
        // the peers beforehand in some unspecified trusted way.
        let mut key_map = BTreeMap::new();
        key_map.insert(name_client.as_bytes().to_vec(), public_client);
        key_map.insert(name_server.as_bytes().to_vec(), public_server);
        let key_map = Rc::new(key_map);

        // The client and the server.
        let mut client = SecureSession::with_transport(
            name_client,
            private_client,
            DummyTransport::new(&key_map),
        ).unwrap();
        let mut server = SecureSession::with_transport(
            name_server,
            private_server,
            DummyTransport::new(&key_map),
        ).unwrap();

        assert!(!client.is_established());
        assert!(!server.is_established());
        assert!(client.get_remote_id().unwrap().is_empty());
        assert!(server.get_remote_id().unwrap().is_empty());

        // Connection and key negotiation sequence.
        let connect_request = client.generate_connect_request().expect("connect request");
        let connect_reply = server.negotiate(&connect_request).expect("connect reply");
        let key_proposed = client.negotiate(&connect_reply).expect("key proposed");
        let key_accepted = server.negotiate(&key_proposed).expect("key accepted");
        let key_confirmed = client.negotiate(&key_accepted).expect("key confirmed");
        assert!(key_confirmed.is_empty());

        assert!(client.is_established());
        assert!(server.is_established());
        assert_eq!(client.get_remote_id().unwrap(), name_server.as_bytes());
        assert_eq!(server.get_remote_id().unwrap(), name_client.as_bytes());

        // TODO: check connection states reported to transport delegate

        // Try sending a message back and forth.
        let plaintext = b"test message please ignore";

        let wrapped = client.wrap(&plaintext).expect("wrap 1 -> 2 message");
        let unwrapped = server.unwrap(&wrapped).expect("unwrap 1 -> 2 message");
        assert_eq!(unwrapped, plaintext);

        let wrapped = server.wrap(&plaintext).expect("wrap 2 -> 1 message");
        let unwrapped = client.unwrap(&wrapped).expect("unwrap 2 -> 1 message");
        assert_eq!(unwrapped, plaintext);

        // TODO: it seems that one cannot wrap an empty message, check it out

        // Messages are independent, can come out-of-order and be lost.
        client.wrap(b"some message").expect("lost message 1");
        client.wrap(b"some message").expect("lost message 2");
        server.wrap(b"some message").expect("lost message 3");

        let wrapped1 = client.wrap(b"message 1").expect("message 1");
        let wrapped2 = client.wrap(b"message 2").expect("message 2");
        let unwrapped2 = server.unwrap(&wrapped2).expect("message 2");
        let unwrapped1 = server.unwrap(&wrapped1).expect("message 1");
        assert_eq!(unwrapped1, b"message 1");
        assert_eq!(unwrapped2, b"message 2");
    }

    #[test]
    fn with_transport() {
        // Peer credentials. Secure Session supports only ECDSA.
        // TODO: tests that confirm RSA failure
        let (private_client, public_client) = gen_ec_key_pair().unwrap();
        let (private_server, public_server) = gen_ec_key_pair().unwrap();
        let (name_client, name_server) = ("client", "server");

        // Shared storage of public peer credentials. These should be communicated between
        // the peers beforehand in some unspecified trusted way.
        let mut key_map = BTreeMap::new();
        key_map.insert(name_client.as_bytes().to_vec(), public_client);
        key_map.insert(name_server.as_bytes().to_vec(), public_server);
        let key_map = Rc::new(key_map);

        // The client and the server.
        let (transport_client, transport_server) = ChannelTransport::new(&key_map);
        let mut client =
            SecureSession::with_transport(name_client, private_client, transport_client).unwrap();
        let mut server =
            SecureSession::with_transport(name_server, private_server, transport_server).unwrap();

        assert!(!client.is_established());
        assert!(!server.is_established());

        // Establishing connection.
        client.connect().expect("client-side connection");
        server.negotiate_transport().expect("connect reply");
        client.negotiate_transport().expect("key proposed");
        server.negotiate_transport().expect("key accepted");
        client.negotiate_transport().expect("key confirmed");

        assert!(client.is_established());
        assert!(server.is_established());

        // Try sending a message back and forth.
        let message = b"test message please ignore";
        client.send(&message).expect("send message");

        let received = server.receive(1024).expect("receive message");

        assert_eq!(received, message);
    }
}
