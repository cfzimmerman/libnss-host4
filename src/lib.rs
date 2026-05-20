#![no_std]

mod buf;
pub mod err;

use core::{
    ffi::CStr,
    net::{Ipv4Addr, Ipv6Addr},
};

use crate::{
    buf::Gaih4Buf,
    err::{NssErr, NssStatus},
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
    if name == core::ptr::null()
        || pat == core::ptr::null_mut()
        || buffer == core::ptr::null_mut()
        || errnop == core::ptr::null_mut()
        || h_errnop == core::ptr::null_mut()
    // Allow null ttlp
    {
        return NssStatus::Unavailable as i32;
    }

    let hostname = unsafe {
        // Hostname is a valid c string.
        CStr::from_ptr(name)
    };

    let (pat, errnop, h_errnop) = unsafe {
        // These are required inputs.
        (&mut *pat, &mut *errnop, &mut *h_errnop)
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
        return NssErr::INVALID_INPUT.bail(errnop, h_errnop);
    };

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

    if ttlp != core::ptr::null_mut() {
        if let Some(user_ttlp) = ToDo::set_ttlp(hostname) {
            unsafe {
                *ttlp = user_ttlp;
            }
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
