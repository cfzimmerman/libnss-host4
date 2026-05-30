//! Implementing the trait and macro in this crate will publish a
//! `gethostbyname4_r` NSS hook in your Rust `cdylib`.
//!
//! # Example
//!
//! ```
//! use libnss_host4::{Addr, HostResolver, err::NssErr, impl_gethostbyname4_r};
//! use std::net::Ipv6Addr;
//!
//! /// This resolver maps "localhost" to [::1%0].
//! struct LocalDns;
//! impl_gethostbyname4_r!(local, LocalDns);
//!
//! impl HostResolver for LocalDns {
//!     fn resolve_host(hostname: &str) -> Result<impl IntoIterator<Item = Addr>, NssErr> {
//!         if hostname == "localhost" {
//!             return Ok([Addr {
//!                 ip: Ipv6Addr::LOCALHOST.into(),
//!                 scope_id: 0,
//!             }]);
//!         }
//!         Err(NssErr::NO_RESULT)
//!     }
//! }
//! ```
//!
//! # Background
//!
//! glibc defines a Name Service Switch interface for querying hostnames.
//!
//! <https://sourceware.org/glibc/manual/2.43/html_mono/libc.html#Host-Names>
//!
//! This once-simple lookup API has unfortunately degenerated into a sedimentary
//! chaos of numbered functions differentiated by reentrance and lack thereof.
//! An early indication of which is the conspicuous absence of `gethostbyname3_r`
//! and `gethostbyname4_r` in the docs linked above.
//!
//! However, as of writing, `gethostbyname4_r` is the only NSS host hook that
//! can return IPv6 addresses with a `scope_id`, which makes it a big deal
//! for the chosen few who care about such things.
//!
//! Other Rust NSS usage is already well supported by the [libnss crate](https://crates.io/crates/libnss).
//! The motivating cause for this crate cannot accomodate its GPL license,
//! which is why this is standalone. Presumably both crates can be used in
//! the same `cdylib` to cover the full NSS host API.
//!
//! If the other hooks aren't needed, though, a cdylib with just `gethostbyname4_r`
//! is sufficient for `getaddrinfo`-based resolution via `/etc/nsswitch.conf`.

// This crate was previously `no_std`. It still could be if not for `std::panic::catch_unwind`.
// But `catch_unwind` is warranted since uncaught panic across FFI is terrible,
// especially in the types of apps that use NSS hooks. Panic is unavoidably possible
// since this wraps unknown user code.

mod buf;
pub mod err;

use core::ffi::CStr;
use core::net::Ipv4Addr;
use core::net::Ipv6Addr;
use std::net::IpAddr;

use crate::buf::Gaih4Buf;
use crate::err::NssErr;
use crate::err::NssStatus;

#[doc(hidden)]
pub mod _macro_internal {
    pub use paste;
}

/// This macro expands into an NSS-compatible hook for the `gethostbyname4_r`
/// hostname resolution API.
///
/// # Safety
///
/// There must not be any other exported function named `_nss_{name}_gethostbyname4_r`
/// in your `cdylib`.
#[macro_export]
macro_rules! impl_gethostbyname4_r {
    ($nss_name:ident, $resolver:ident) => {
        $crate::_macro_internal::paste::paste! {
            #[unsafe(no_mangle)]
            pub unsafe extern "C" fn [<_nss_ $nss_name _gethostbyname4_r>](
                name: *const ::libc::c_char,
                pat: *mut *mut $crate::GaihAddrTuple,
                buffer: *mut ::libc::c_char,
                buflen: ::libc::size_t,
                errnop: *mut ::libc::c_int,
                h_errnop: *mut ::libc::c_int,
                ttlp: *mut ::libc::c_int,
            ) -> ::libc::c_int {
                std::panic::catch_unwind(|| {
                    unsafe { $crate::gethostbyname4_r::<$resolver>(name, pat, buffer, buflen, errnop, h_errnop, ttlp) }
                }).unwrap_or_else(|_| {
                    unsafe {
                        if !errnop.is_null() {
                            *errnop = ::libc::EIO;
                        }
                        if !h_errnop.is_null() {
                            *h_errnop = $crate::err::HostStatus::NoRecovery as i32;
                        }
                    }
                    $crate::err::NssStatus::Unavailable as i32
                })
            }
        }
    };
}

/// An address that can be returned from gethostbyname4_r.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct Addr {
    /// The IP address that was resolved.
    pub ip: IpAddr,

    /// This is typically only used for IPv6.
    ///
    /// Zero is a safe default if you're using IPv4 or don't know
    /// what to put here.
    //
    // Leaving this as an option in IPv4 to enable whatever shenanigans
    // the API user might be up to.
    pub scope_id: u32,
}

/// Implement this trait with the actual address business logic
/// that `gethostbyname4_r` should expose. The C interop layer
/// simply wraps the resolution defined here.
pub trait HostResolver {
    /// Returns zero or more host addresses matching the hostname query
    /// or an NSS-contextualized error on failure.
    fn resolve_host(hostname: &str) -> Result<impl IntoIterator<Item = Addr>, NssErr>;

    /// Optionally sets the "Time to Live Pointer" for the given
    /// hostname's NSS result. This influences address cache lifespan.
    ///
    /// It is perfectly fine to ignore this. Only implement it if you
    /// have a reason.
    ///
    /// This function is only invoked if the caller's TTLP is not null,
    /// and returning None will skip writing to the pointer entirely.
    fn set_ttlp(hostname: &str) -> Option<i32> {
        let _ = hostname;
        None
    }
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
/// it may also be a useful reference for others implementing NSS hooks.
///
/// # Safety
///
/// This function should never be called outside the NSS lookup path.
/// Within glibc NSS, this implementation expects the following:
///
/// - `name` is a valid C string.
/// - `*pat` is always a valid pointer. `**pat` may be either NULL or a valid
///   `GaihAddrTuple` into which the first NSS result is written. The caller
///   will only explore this list if it receives a success return value.
/// - `buffer` + `buflen` are equivalent to a `&mut [u8]` with all the expectations
///   byte slices carry in safe rust.
/// - `errnop` and `h_errnop` are safe to dereference.
/// - `ttlp` is either NULL or safe to dereference.
///
/// # Returns
///
/// Return value is an enum defined here:
///
/// <https://github.com/lattera/glibc/blob/895ef79e04a953cac1493863bcae29ad85657ee1/nss/nss.h#L30-L38>
#[inline]
#[doc(hidden)]
pub unsafe fn gethostbyname4_r<R: HostResolver>(
    // The hostname to be resolved. This is a null-terminated C-string and
    // must not be used in the returned gaih_addrtuple. The gaih_addrtuple
    // name should be stored within the given return buffer:
    //
    // https://github.com/avahi/nss-mdns/blob/3292b172ce0100a1aed8b67c381760bc3fb87f2e/src/util.c#L234-L236
    name: *const libc::c_char,

    // "Pointer to Address Tuple"
    // Pointer to the linked list node in which this function's results are stored.
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

    // "Host" lookup errno. Extends the standard errno.
    //
    // https://github.com/lattera/glibc/blob/895ef79e04a953cac1493863bcae29ad85657ee1/resolv/netdb.h#L62-L69
    h_errnop: *mut libc::c_int,

    // DNS time to live hint.
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
    if name.is_null() || pat.is_null() || buffer.is_null() || errnop.is_null() || h_errnop.is_null()
    // Allow null ttlp
    {
        return NssStatus::Unavailable as i32;
    }

    let (hostname, pat, errnop, h_errnop) = unsafe {
        (
            CStr::from_ptr(name),
            &mut *pat,
            &mut *errnop,
            &mut *h_errnop,
        )
    };

    let maybe_buf = unsafe { Gaih4Buf::try_new(hostname, pat, buffer, buflen) };
    let mut buffer = match maybe_buf {
        Ok(b) => b,
        Err(e) => return e.bail(errnop, h_errnop),
    };

    let Ok(hostname) = hostname.to_str() else {
        // Require a UTF-8 hostname.
        return NssErr::INVALID_INPUT.bail(errnop, h_errnop);
    };

    let addrs = match R::resolve_host(hostname) {
        Ok(res) => res,
        Err(e) => return e.bail(errnop, h_errnop),
    };

    let mut found = false;
    for addr in addrs {
        if !buffer.push(addr) {
            return NssErr::BUF_TOO_SMALL.bail(errnop, h_errnop);
        }
        found = true;
    }

    if !found {
        return NssErr::NO_RESULT.bail(errnop, h_errnop);
    }

    if !ttlp.is_null()
        && let Some(user_ttlp) = R::set_ttlp(hostname)
    {
        unsafe {
            *ttlp = user_ttlp;
        }
    }

    NssErr::SUCCESS.bail(errnop, h_errnop)
}

/// Recursive host object returned from `gethostbyname4`.
///
/// Defined in `nss.h`.
///
/// <https://github.com/lattera/glibc/blob/895ef79e04a953cac1493863bcae29ad85657ee1/nss/nss.h#L42-L49>
#[repr(C)]
#[derive(Debug)]
#[doc(hidden)]
pub struct GaihAddrTuple {
    next: *mut GaihAddrTuple,
    name: *const libc::c_char,
    family: libc::c_int,

    /// Stored big endian.
    ///
    /// <https://www.man7.org/linux/man-pages/man3/gethostbyname.3.html#:~:text=address%20in%20bytes.-,h_addr_list,-An%20array%20of>
    addr: [libc::c_uint; 4],

    /// Stored native endian.
    ///
    /// <https://sourceware.org/glibc/manual/2.41/html_node/Internet-Address-Formats.html#:~:text=The%20scope%20ID%20is%20stored%20in%20host%20byte%20order>
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
        let mut pat = match addr.ip {
            IpAddr::V4(v4) => Self::new_v4(hostname, v4),
            IpAddr::V6(v6) => Self::new_v6(hostname, v6),
        };
        pat.scope_id = addr.scope_id;
        pat
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
    fn new_v6(hostname: *const libc::c_char, ipv6: Ipv6Addr) -> Self {
        let mut pat = Self::new(hostname);
        pat.family = libc::AF_INET6;

        ipv6.octets()
            .chunks_exact(4)
            .map(|bits| <[_; 4]>::try_from(bits).expect("exact chunk size is four"))
            .map(u32::from_ne_bytes)
            .zip(&mut pat.addr)
            .for_each(|(val, slot)| *slot = val);

        pat
    }
}

#[cfg(test)]
mod conversion_tests {
    use core::net::Ipv4Addr;
    use core::net::Ipv6Addr;

    use crate::GaihAddrTuple;

    /// NSS expects `gaih_addrtuple.addr` to hold the address in
    /// big endian order. This test verifies with a direct conversion.
    #[test]
    fn ipv4_addr_is_network_byte_order() {
        let t = GaihAddrTuple::new_v4(core::ptr::null(), Ipv4Addr::LOCALHOST);
        let bytes: [u8; 16] = unsafe { core::mem::transmute(t.addr) };
        assert_eq!(bytes[..4], Ipv4Addr::LOCALHOST.octets());
    }

    // IPv6 equivalent of the test above
    #[test]
    fn ipv6_addr_is_network_byte_order() {
        let t = GaihAddrTuple::new_v6(core::ptr::null(), Ipv6Addr::LOCALHOST);
        let bytes: [u8; 16] = unsafe { core::mem::transmute(t.addr) };
        assert_eq!(bytes, Ipv6Addr::LOCALHOST.octets());
    }
}
