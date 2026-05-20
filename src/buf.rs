use core::{ffi::CStr, mem::MaybeUninit};

use crate::{
    Addr, GaihAddrTuple,
    err::{NssErr, NssRes},
};

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
    //   every entry in the buffer will reference that hostname
    //   pointer.
    // - Defines an aligned section of the buffer after the hostname
    //   into which addr results are written.
    // - Returns that as a special buffer into which results can be
    //   accumulated.
    pub(crate) unsafe fn try_new(
        hostname: &CStr,
        maybe_head: &'a mut *mut GaihAddrTuple,
        buffer: *mut libc::c_char,
        buf_len: libc::size_t,
    ) -> NssRes<Self> {
        assert_ne!(buffer, core::ptr::null_mut(), "buffer is not null");

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
            // Offset is a usize, so this only fails if isize::MAX < offset.
            // That should never happen in reality, but this gives a more
            // mathematically robust API.
            let offset_bytes = isize::try_from(offset_bytes).unwrap_or(isize::MAX);

            let arr_start = unsafe {
                // This offset is guaranteed to point to allocated memory because
                // offset and therefore arr_len are nonzero.
                buffer.offset(offset_bytes)
            };

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

    /// Attempts to add an address to the
    pub(crate) fn push(&mut self, addr: Addr) -> bool {
        if *self.maybe_head != core::ptr::null_mut() && !self.set_head {
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
                    *self.maybe_head == core::ptr::null_mut(),
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
