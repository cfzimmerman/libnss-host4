#![no_std]

use core::{
    ffi::CStr,
    mem::{self, MaybeUninit},
    net::{Ipv4Addr, Ipv6Addr},
};

pub enum Addr {
    V4(Ipv4Addr),
    V6 { ip: Ipv6Addr, scope_id: u32 },
}

pub type NssRes<T> = Result<T, NssErr>;

pub struct NssErr {
    /// A standard libc error.
    c_err: i32,
    nss: NssStatus,
    dns: DnsStatus,
}

impl NssErr {
    /// The buffer containing requests results was too small. Retrying
    /// with a larger buffer may succeed.
    pub const BUF_TOO_SMALL: Self = Self {
        c_err: libc::EAGAIN,
        nss: NssStatus::TryAgain,
        dns: DnsStatus::TryAgain,
    };
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
unsafe extern "C" fn _nss_todo_gethostbyname4_r(
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
    todo!()
}

pub trait GetAddrInfo {
    fn get_host(hostname: &str) -> Result<impl Iterator<Item = Addr>, NssErr>;
}

/// Recursive host object returned from `gethostbyname4`.
///
/// Defined in `nss.h`.
/// https://github.com/lattera/glibc/blob/895ef79e04a953cac1493863bcae29ad85657ee1/nss/nss.h#L42-L49
#[repr(C)]
#[derive(Debug)]
struct GaihAddrTuple {
    next: *mut GaihAddrTuple,
    name: *const libc::c_char,
    family: libc::c_int,
    addr: [libc::c_int; 4],
    scope_id: libc::c_int,
}

impl GaihAddrTuple {
    fn new(hostname: *const libc::c_char) -> Self {
        Self {
            next: core::ptr::null_mut(),
            name: hostname,
            family: libc::AF_INET6,
            addr: [0i32; 4],
            scope_id: 0,
        }
    }
}

struct Gaih4Buf<'a> {
    hostname: *const libc::c_char,
    maybe_head: *mut *mut GaihAddrTuple,
    addrs: &'a [MaybeUninit<GaihAddrTuple>],
    addrs_len: usize,
}

impl<'a> Gaih4Buf<'a> {
    /// Constructs a new buffer for accumulating address results.
    ///
    /// Expects the parameters exactly as given to gethostbyname4_r
    /// except hostname, which should be cleaned up into a CStr.
    //
    // Steps:
    // - Writes the hostname string into the front of the buffer.
    //   every entry in the buffer will reference that hostname
    //   pointer.
    // - Defines an aligned section of the buffer after the hostname
    //   into which addr results are written.
    // - Returns that as a special buffer into which results can be
    //   accumulated.
    pub fn try_new(
        hostname: &CStr,
        maybe_head: *mut *mut GaihAddrTuple,
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
                core::ptr::copy_nonoverlapping(hostname.as_ptr(), buffer.cast(), host_len);
            };

            (buffer as *const libc::c_char, host_len)
        };

        let offset = name_len.next_multiple_of(core::mem::align_of::<GaihAddrTuple>());
        let arr_len = buf_len.saturating_sub(offset) / core::mem::size_of::<GaihAddrTuple>();

        let addrs = if arr_len == 0 {
            &mut []
        } else {
            // Offset is a usize, so this only fails if offset < isize::MAX. That should never happen
            // in reality, but this gives a more mathematically robust API.
            let offset = isize::try_from(offset).unwrap_or(isize::MAX);

            let arr_start = unsafe {
                // This offset is guaranteed to point to allocated memory because
                // offset and therefore arr_len are nonzero.
                buffer.offset(offset)
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
            maybe_head,
            addrs,
            addrs_len: 0,
        })
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
