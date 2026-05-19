#![no_std]

use core::{
    ffi::CStr,
    mem::MaybeUninit,
    net::{Ipv4Addr, Ipv6Addr},
};

/// An address that can be returned from gethostbyname4_r.
pub enum Addr {
    V4(Ipv4Addr),
    V6 {
        ip: Ipv6Addr,

        /// Zero is a safe default if you don't know what to put here.
        scope_id: u32,
    },
}

pub type NssRes<T> = Result<T, NssErr>;

/// Contains the return information passed by this plugin
/// through the NSS API.
///
/// Some common constants are defined, but feel free to
/// construct your own as well.
pub struct NssErr {
    /// A standard libc error.
    c_err: i32,
    nss: NssStatus,
    dns: DnsStatus,
}

impl NssErr {
    /// The command succeeded. No error.
    pub const SUCCESS: Self = Self {
        c_err: 0,
        nss: NssStatus::Success,
        dns: DnsStatus::Success,
    };

    /// This can be returned when the plugin successfully ran and found
    /// no matches for the hostname.
    pub const NO_RESULT: Self = Self {
        c_err: 0,
        nss: NssStatus::NotFound,
        dns: DnsStatus::NoData,
    };

    /// For example, a hostname is not valid UTF-8, which is expected
    /// by this library and most (all?) DNS services.
    pub const INVALID_HOSTNAME: Self = Self {
        c_err: libc::EINVAL,
        nss: NssStatus::Unavailable,
        dns: DnsStatus::NoRecovery,
    };

    /// This is a suitable return type for total plugin failure. For example,
    /// if you're relying on unix sockets to communicate with a DNS server and
    /// there are failures talking to the server.
    pub const PLUGIN_FAILED: Self = Self {
        // IO is somewhat questionable here. Feel free to overwrite it
        // with something more appropriate for your context.
        c_err: libc::EIO,
        nss: NssStatus::Unavailable,
        dns: DnsStatus::NoRecovery,
    };

    /// The buffer containing requests results was too small. Retrying
    /// with a larger buffer may succeed.
    const BUF_TOO_SMALL: Self = Self {
        c_err: libc::EAGAIN,
        nss: NssStatus::TryAgain,
        dns: DnsStatus::TryAgain,
    };

    /// Writes error state to return pointers and yields the appropriate
    /// NSS exit code for this error.
    fn bail(self, errnop: &mut libc::c_int, h_errnop: &mut libc::c_int) -> libc::c_int {
        *errnop = self.c_err;
        *h_errnop = self.dns as i32;
        self.nss as i32
    }
}

/// Return status of an NSS function call.
///
/// Defined here:
/// <https://github.com/lattera/glibc/blob/895ef79e04a953cac1493863bcae29ad85657ee1/nss/nss.h#L30-L38>
pub enum NssStatus {
    /// This service is temporarily unusable. For example, the given address
    /// buffer is too small or the backing DNS service is overloaded.
    TryAgain = -2,

    /// Plugin failure. For example, IPC or connectivity to some backing
    /// DNS service failed.
    Unavailable,

    /// The query completed successfully without returning any matching hosts.
    /// Pairs with [`DnsStatus::HostNotFound`].
    NotFound,

    /// Request succeeded. Caller should check PAT list.
    Success,
    //
    // Don't use `RETURN`? nss-mdns never does, and some cursory searching
    // suggests plugins should not return this value.
    // Return,
}

/// Defined here. Comments copied verbatim:
///
/// <https://github.com/lattera/glibc/blob/895ef79e04a953cac1493863bcae29ad85657ee1/resolv/netdb.h#L62-L75>
pub enum DnsStatus {
    /// See errno.
    Internal = -1,

    /// No problem
    Success,

    /// Authoritative Answer Host not found.
    HostNotFound,

    /// Non-Authoritative Host not found or SERVERFAIL.
    TryAgain,

    /// Non recoverable errors, FORMERR, REFUSED, NOTIMP.
    NoRecovery,

    /// Valid name, no data record of requested type.
    NoData,
}

/// GETHOSTBYNAME4_R
///
/// This majestically-named function is used by glibc's `getaddrinfo`
/// lookup when the "simple, old functions" are unsuitable. The motivating
/// case is IPv6 scope IDs:
///
/// <https://github.com/lattera/glibc/blob/895ef79e04a953cac1493863bcae29ad85657ee1/sysdeps/posix/getaddrinfo.c#L563-L565>
///
/// Authoritative docs for implementing this API were elusive, so this
/// effort is based largely on avahi nss-mdns source. My own understanding of
/// this API is documented here in-excess with the hope that anything incorrect
/// can be swiftly identified and fixed. If it is somehow fully correct, then
/// it may also be a useful reference for others exploring this API.
///
/// # Returns
///
/// Return value is an enum defined here:
///
/// <https://github.com/lattera/glibc/blob/895ef79e04a953cac1493863bcae29ad85657ee1/nss/nss.h#L30-L38>
pub unsafe extern "C" fn _nss_todo_gethostbyname4_r(
    // The hostname to be resolved. This is a null-terminated C-string and
    // must not be used in the returned gaih_addrtuple. The gaih_addrtuple
    // name should be stored within the given buffer:
    //
    // https://github.com/avahi/nss-mdns/blob/3292b172ce0100a1aed8b67c381760bc3fb87f2e/src/util.c#L234-L236
    name: *const libc::c_char,

    // "Pointer to Address Tuple"
    // Pointer to the linked list in which this function's results are stored.
    // Said list must live entirely within the given buffer.
    //
    // HOWEVER, if `*pat` is not null, then the first node in the list should
    // be placed there, and all subsequent nodes should live in the buffer.
    //
    // https://github.com/avahi/nss-mdns/blob/3292b172ce0100a1aed8b67c381760bc3fb87f2e/src/util.c#L242-L255
    pat: *mut *mut GaihAddrTuple,

    // A buffer in which all results must be stored including the hostname.
    buffer: *mut libc::c_char,

    // The length of this buffer in bytes.
    buflen: libc::size_t,

    // A canonical linux error code.
    errnop: *mut libc::c_int,

    // DNS error among those enumerated here:
    // https://github.com/lattera/glibc/blob/895ef79e04a953cac1493863bcae29ad85657ee1/resolv/netdb.h#L62-L69
    h_errnop: *mut libc::c_int,

    // Time to live hint.
    //
    // NCSD initializes it to i32::MAX.
    //
    // https://github.com/lattera/glibc/blob/895ef79e04a953cac1493863bcae29ad85657ee1/nscd/aicache.c#L119
    //
    // And nss-mdns just ignores it.
    //
    // https://github.com/avahi/nss-mdns/blob/3292b172ce0100a1aed8b67c381760bc3fb87f2e/src/nss.c#L164
    ttlp: *mut libc::c_int,
) -> libc::c_int {
    let hostname = unsafe {
        // The contract is that name is a c string. We have to trust that.
        CStr::from_ptr(name)
    };
    let pat = unsafe {
        // The caller must give us a legit pointer. Otherwise there's no place
        // their results could be stored. This is again part of the API contract.
        &mut *pat
    };
    let (errnop, h_errnop, ttlp) = unsafe {
        // Again we just have to trust these are safe to use.
        (&mut *errnop, &mut *h_errnop, &mut *ttlp)
    };

    let maybe_buf = unsafe {
        // Trust the input buffer is properly defined.
        Gaih4Buf::try_new(hostname, pat, buffer, buflen)
    };

    let mut buffer = match maybe_buf {
        Ok(b) => b,
        Err(e) => return e.bail(errnop, h_errnop),
    };

    let Ok(hostname) = hostname.to_str() else {
        return NssErr::INVALID_HOSTNAME.bail(errnop, h_errnop);
    };

    if let Some(user_ttlp) = ToDo::set_ttlp(hostname) {
        *ttlp = user_ttlp;
    }

    let addrs = match ToDo::resolve_host(hostname) {
        Ok(res) => res,
        Err(e) => return e.bail(errnop, h_errnop),
    };

    let mut count = 0;
    for addr in addrs {
        count += 1;
        if !buffer.push(addr) {
            return NssErr::BUF_TOO_SMALL.bail(errnop, h_errnop);
        }
    }

    if count == 0 {
        return NssErr::NO_RESULT.bail(errnop, h_errnop);
    }
    NssErr::SUCCESS.bail(errnop, h_errnop)
}

pub trait GetAddrInfo {
    /// Resolves the
    fn resolve_host(hostname: &str) -> Result<impl Iterator<Item = Addr>, NssErr>;

    fn set_ttlp(hostname: &str) -> Option<i32> {
        let _ = hostname;
        None
    }
}

struct ToDo;

impl GetAddrInfo for ToDo {
    fn resolve_host(_hostname: &str) -> Result<impl Iterator<Item = Addr>, NssErr> {
        Ok(core::iter::empty())
    }
}

/// Recursive host object returned from `gethostbyname4`.
///
/// Defined in `nss.h`.
/// https://github.com/lattera/glibc/blob/895ef79e04a953cac1493863bcae29ad85657ee1/nss/nss.h#L42-L49
#[repr(C)]
#[derive(Debug)]
pub struct GaihAddrTuple {
    next: *mut GaihAddrTuple,
    name: *const libc::c_char,
    family: libc::c_int,
    // This is actually defined as [int; 4], but I don't expect FFI will mind this...
    addr: [libc::c_uint; 4],
    scope_id: libc::c_uint,
}

impl GaihAddrTuple {
    fn new(hostname: *const libc::c_char) -> Self {
        Self {
            next: core::ptr::null_mut(),
            name: hostname,
            family: libc::AF_UNSPEC,
            addr: [0u32; 4],
            scope_id: 0,
        }
    }

    /// Constructs a new node for the given address.
    fn new_addr(hostname: *const libc::c_char, addr: Addr) -> Self {
        match addr {
            Addr::V4(ipv4) => Self::new_v4(hostname, ipv4),
            Addr::V6 { ip, scope_id } => Self::new_v6(hostname, ip, scope_id),
        }
    }

    /// Constructs a new IPv4 address node.
    fn new_v4(hostname: *const libc::c_char, ipv4: Ipv4Addr) -> Self {
        // This and `new_v6` are informed by avahi's use of inet_pton.
        // https://github.com/avahi/nss-mdns/blob/3292b172ce0100a1aed8b67c381760bc3fb87f2e/src/avahi.c#L108

        let mut pat = Self::new(hostname);
        pat.family = libc::AF_INET;
        pat.addr[0] = u32::from_ne_bytes(ipv4.octets());
        pat
    }

    /// Constructs a new IPv6 address node.
    fn new_v6(hostname: *const libc::c_char, ipv6: Ipv6Addr, scope_id: u32) -> Self {
        let mut pat = Self::new(hostname);
        pat.family = libc::AF_INET6;
        pat.scope_id = scope_id;

        let addr = ipv6.octets();
        let segs = addr.chunks_exact(4).map(|bytes| {
            let arr: &[u8; 4] = bytes
                .try_into()
                .expect("IPv6 address contains four groups of four bytes");
            u32::from_ne_bytes(*arr)
        });
        for (src, dst) in segs.zip(&mut pat.addr) {
            *dst = src;
        }

        pat
    }
}
/*
https://github.com/avahi/nss-mdns/blob/3292b172ce0100a1aed8b67c381760bc3fb87f2e/src/avahi.c#L108
*/

/// This is the buffer into which gethostbyname4_r results are accumulated.
///
/// gethostbyname4_r passes a buffer where results should be written. Those
/// results include the resolved hostname and a linked list of address
/// nodes. This struct is effectively a single-purpose allocator for
/// constructing the gethostbyname4_r return type.
struct Gaih4Buf<'a> {
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
    pub unsafe fn try_new(
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

        let offset_bytes = name_len.next_multiple_of(core::mem::align_of::<GaihAddrTuple>());
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
    pub fn push(&mut self, addr: Addr) -> bool {
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

        let prev_len = self.addrs_len;
        self.addrs_len += 1;

        match prev_len {
            0 if !self.set_head => {}
            0 if self.set_head => unsafe {
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

/*
scratch

oh my: https://github.com/lattera/glibc/blob/895ef79e04a953cac1493863bcae29ad85657ee1/nscd/aicache.c#L139-L150

enum nss_status _nss_mdns_gethostbyname4_r(const char* name,
                                           struct gaih_addrtuple** pat,
                                           char* buffer, size_t buflen,
                                           int* errnop, int* h_errnop,
                                           int32_t* ttlp) {

enum nss_status _nss_mdns_gethostbyname4_r(const char*, struct gaih_addrtuple**,
                                           char*, size_t, int*, int*, int32_t*);

            #[no_mangle]
            unsafe extern "C" fn [<_nss_ $mod_ident _gethostbyname2_r>](
                name: *const libc::c_char,
                family: libc::c_int,
                result: *mut CHost,
                buf: *mut libc::c_char,
                buflen: libc::size_t,
                errnop: *mut libc::c_int,
                h_errnop: *mut libc::c_int
            ) -> libc::c_int {

*/
