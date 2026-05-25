use core::ffi::CStr;
use core::mem::MaybeUninit;

use crate::Addr;
use crate::GaihAddrTuple;
use crate::err::NssErr;
use crate::err::NssRes;

/// This is the buffer into which gethostbyname4_r results are accumulated.
///
/// gethostbyname4_r passes a buffer where results should be written. Those
/// results include the resolved hostname and a linked list of address
/// nodes. This struct is effectively a single-purpose allocator for
/// constructing the gethostbyname4_r return type.
pub(crate) struct Gaih4Buf<'a> {
    hostname: *const libc::c_char,
    addrs: &'a mut [MaybeUninit<GaihAddrTuple>],
    addrs_len: usize,
    maybe_head: &'a mut *mut GaihAddrTuple,
    set_head: bool,
}

impl<'a> Gaih4Buf<'a> {
    /// Constructs a new buffer for accumulating address results.
    ///
    /// Safety:
    /// - hostname should point exactly to the cstring that was given
    ///   to gethostbyname4_r.
    /// - buffer should be exactly the buffer provided to gethostbyname4_r.
    /// - maybe_head should be exactly the `pat` provided to gethostbyname4_r.
    ///
    /// If these are satisfied, then safety depends upon whoever called
    /// gethostbyname4_r.
    //
    // Steps:
    // - Writes the hostname string into the front of the buffer.
    //   Every entry in the buffer will reference that hostname
    //   pointer.
    // - Defines an aligned section of the buffer after the hostname
    //   into which addr results are written.
    // - Returns that as an abstraction into which results can be accumulated.
    pub(crate) unsafe fn try_new(
        hostname: &CStr,
        maybe_head: &'a mut *mut GaihAddrTuple,
        buffer: *mut libc::c_char,
        buf_len: libc::size_t,
    ) -> NssRes<Self> {
        if buffer.is_null() {
            return Err(NssErr::INVALID_INPUT);
        }

        if !(*maybe_head).is_null() {
            unsafe {
                // Assume safe to write if not NULL.
                (**maybe_head).next = core::ptr::null_mut();
            }
        }

        let (hostname, name_len) = {
            let hostname = hostname.to_bytes_with_nul();
            let host_len = hostname.len();
            if buf_len < host_len {
                return Err(NssErr::BUF_TOO_SMALL);
            }

            unsafe {
                // This safety depends on the following:
                // - Hostname was a well-formed C string of entirely initialized memory.
                // - Buffer is a safe buffer of length buflen.
                //
                // Both of these are NSS API contracts, so we have to just trust the caller.
                // Only copying bytes, so alignment is one.
                core::ptr::copy_nonoverlapping(hostname.as_ptr(), buffer.cast(), host_len);
            };

            (buffer as *const libc::c_char, host_len)
        };

        let offset_bytes = (buffer as usize + name_len)
            .next_multiple_of(core::mem::align_of::<GaihAddrTuple>())
            - buffer as usize;
        let arr_len = buf_len.saturating_sub(offset_bytes) / core::mem::size_of::<GaihAddrTuple>();

        let addrs = if arr_len == 0 {
            // Even if we can't store anything in the buffer, we should proceed because
            // there could be space in `maybe_head`. We might also not need space in
            // the buffer if resolution fails for some other reason.
            &mut []
        } else {
            let arr_start = buffer.wrapping_add(offset_bytes);
            if (arr_start as usize) < buffer as usize {
                // Pointer addition wrapped. Cannot continue.
                return Err(NssErr::INVALID_INPUT);
            }

            let arr = arr_start.cast::<MaybeUninit<GaihAddrTuple>>();
            assert_eq!(
                arr as usize % core::mem::align_of::<GaihAddrTuple>(),
                0,
                "arr_start is aligned"
            );
            assert!(
                name_len + arr_len * core::mem::size_of::<GaihAddrTuple>() <= buf_len,
                "name and array fit in the buffer allocation"
            );

            unsafe {
                // Safety verified by assertions above.
                core::slice::from_raw_parts_mut(arr, arr_len)
            }
        };

        Ok(Self {
            hostname,
            addrs,
            addrs_len: 0,
            maybe_head,
            set_head: false,
        })
    }

    /// Attempts to add an address to the buffer.
    ///
    /// Returns true on success and false on failure. After the first
    /// false, a push will never succeed until the NSS caller tries again
    /// with a larger buffer.
    pub(crate) fn push(&mut self, addr: Addr) -> bool {
        if !(*self.maybe_head).is_null() && !self.set_head {
            unsafe {
                // We're trusting that any non-null pointer at maybe_head is
                // okay writing to. This unsafeness is declared in `try_new`, so
                // we can just assume soundness here.
                **self.maybe_head = GaihAddrTuple::new_addr(self.hostname, addr);
            }
            // No parent node to update.
            self.set_head = true;
            return true;
        }

        let child = {
            let Some(slot) = self.addrs.get_mut(self.addrs_len) else {
                return false;
            };
            core::ptr::from_mut(slot.write(GaihAddrTuple::new_addr(self.hostname, addr)))
        };

        self.addrs_len += 1;
        match self.addrs_len {
            0 => unreachable!("addrs_len is incremented above"),
            1 if !self.set_head => {
                assert!(
                    (*self.maybe_head).is_null(),
                    "if PAT were non null, we would have written to it and returned early"
                );
                // Point PAT at the first node in the return buffer.
                *self.maybe_head = child;
                self.set_head = true;
            }
            1 => unsafe {
                // set_head is only true if we've already written to this pointer. In that
                // case we might as well assume it's a good pointer a second time.
                (**self.maybe_head).next = child;
            },
            nonzero => {
                let parent = &mut self.addrs[nonzero - 1];
                unsafe {
                    // We should only be at a nonzero index if we've already
                    // written to the parent.
                    parent.assume_init_mut().next = child;
                }
            }
        }

        true
    }
}

/// Iterating list entries a la NSS caller is a useful
/// feature when testing. However it's not needed for
/// this crate to be useful, and it's yet another source
/// of unsafe blocks. So the iterator is implemented
/// here as cfg test.
#[cfg(test)]
mod buf_iter {
    use core::{
        ffi::CStr,
        marker::PhantomData,
        net::{Ipv4Addr, Ipv6Addr},
    };

    use crate::{Addr, GaihAddrTuple, buf::Gaih4Buf};

    // TODO: resume here by combing this impl and then using it in tests.

    impl<'a> Gaih4Buf<'a> {
        fn iter(&self) -> Gaih4BufIter<'_> {
            let next = if !self.set_head {
                assert_eq!(self.addrs_len, 0);
                core::ptr::null_mut()
            } else {
                *self.maybe_head
            };
            Gaih4BufIter {
                next,
                _t: PhantomData,
            }
        }
    }

    struct Gaih4BufIter<'a> {
        // Using raw pointers in a rust linked list is pretty lame.
        // However the target list is stored entirely within a
        // custom allocator, so the usual suspect rust primitives for
        // fancier list construction are less attractive.
        next: *mut GaihAddrTuple,
        _t: PhantomData<&'a Gaih4Buf<'a>>,
    }

    impl<'a> Iterator for Gaih4BufIter<'a> {
        type Item = (&'a str, Addr);

        fn next(&mut self) -> Option<Self::Item> {
            if self.next.is_null() {
                return None;
            }
            let node = unsafe {
                // Safety is a chain: first the inputs were well formed, and
                // then the buffer's list is well formed. If both are the case,
                // then this progresses to the next initialized node in the buffer.
                &mut *self.next
            };
            self.next = node.next;
            let name = unsafe {
                // Each node's name should be the input hostname copied
                // directly into the output buffer.
                CStr::from_ptr(node.name)
            };
            let name = name.to_str().expect("CStr should be valid utf8");

            let addr = match node.family {
                libc::AF_INET => Addr::V4(Ipv4Addr::from_bits(node.addr[0])),
                libc::AF_INET6 => {
                    let mut bytes = node
                        .addr
                        .iter()
                        .flat_map(|int| int.to_ne_bytes().into_iter());
                    let bytes: [u8; 16] = core::array::from_fn(|_| {
                        bytes
                            .next()
                            .expect("should be enough bytes for an IPv6 addr")
                    });
                    Addr::V6 {
                        ip: Ipv6Addr::from_octets(bytes),
                        scope_id: node.scope_id,
                    }
                }
                other => panic!("valid nodes are only ever IPv4 or IPv6. Found libc::AF_{other}"),
            };

            Some((name, addr))
        }
    }
}

#[cfg(test)]
mod buf_tests {
    use crate::{Addr, GaihAddrTuple, buf::Gaih4Buf};
    use core::{
        ffi::CStr,
        net::{Ipv4Addr, Ipv6Addr},
    };

    #[test]
    fn good_addrs_seed_pat() {
        const ADDRS4: &[u32] = &[111, 222, 333];
        const ADDRS6: &[u128] = &[777, 888, 999];

        const HOSTNAME: &CStr = c"AMBIGUOUS_NEIGHBOR";
        let mut pat = core::pin::pin!(GaihAddrTuple {
            next: core::ptr::null_mut(),
            name: core::ptr::null(),
            family: libc::AF_UNSPEC,
            addr: [0; 4],
            scope_id: 0,
        });
        let mut pat_ptr = &raw mut *pat;
        let mut bytes = core::pin::pin!([0i8; 512]);

        let mut buf =
            unsafe { Gaih4Buf::try_new(HOSTNAME, &mut pat_ptr, bytes.as_mut_ptr(), bytes.len()) }
                .expect("well formed inputs should be successful");

        for addr in ADDRS4.iter().copied().map(Ipv4Addr::from_bits) {
            let success = buf.push(Addr::V4(addr));
            assert!(success, "v4 push should succeed");
        }

        for (scope_id, ip) in ADDRS6.iter().copied().map(Ipv6Addr::from_bits).enumerate() {
            let success = buf.push(Addr::V6 {
                ip,
                scope_id: scope_id as u32,
            });
            assert!(success, "v6 push should succeed");
        }
    }
}
