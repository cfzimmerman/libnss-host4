//! `gethostbyname4_r` has three dimensions of return state
//! defined in this module.
//!
//! - [`NssStatus`] is returned directly by the function.
//! - [`HostStatus`] contextualizes an NSS host lookup result.
//! - A [`libc`] return code explains general errors.
//!
//! The [`NssErr`] type holds all three and communicates them
//! to the NSS caller as possible. Some common situations are
//! already defined as constants in [`NssErr`].

pub type NssRes<T> = Result<T, NssErr>;

/// Contains the return information passed by this plugin
/// through the NSS API.
///
/// Some common constants are defined, but feel free to
/// construct your own as well.
#[derive(Debug, PartialEq, Eq)]
pub struct NssErr {
    /// A standard libc error.
    pub c_err: i32,
    pub nss: NssStatus,
    pub dns: HostStatus,
}

impl NssErr {
    /// The command succeeded with results.
    pub const SUCCESS: Self = Self {
        c_err: 0,
        nss: NssStatus::Success,
        dns: HostStatus::Success,
    };

    /// The plugin completed successfully and found no matches for the hostname.
    pub const NO_RESULT: Self = Self {
        c_err: 0,
        nss: NssStatus::NotFound,
        dns: HostStatus::NoData,
    };

    /// The macro wrapper returns this when a hostname is not valid UTF-8,
    /// which is expected by this library.
    pub const INVALID_INPUT: Self = Self {
        c_err: libc::EINVAL,
        nss: NssStatus::Unavailable,
        dns: HostStatus::NoRecovery,
    };

    /// This is a suitable return type for total failure.
    /// For example, if there are I/O failures communicating with
    /// an external DNS server.
    pub const PLUGIN_FAILED: Self = Self {
        // IO is questionable here. Feel free to overwrite it
        // with something more appropriate for your context.
        c_err: libc::EIO,
        nss: NssStatus::Unavailable,
        dns: HostStatus::NoRecovery,
    };

    /// The buffer containing request results was too small. Retrying
    /// with a larger buffer may succeed.
    pub(crate) const BUF_TOO_SMALL: Self = Self {
        c_err: libc::EAGAIN,
        nss: NssStatus::TryAgain,
        dns: HostStatus::TryAgain,
    };

    /// Writes error state to return pointers and yields the appropriate
    /// NSS exit code for this error.
    pub(crate) fn bail(self, errnop: &mut libc::c_int, h_errnop: &mut libc::c_int) -> libc::c_int {
        *errnop = self.c_err;
        *h_errnop = self.dns as i32;
        self.nss as i32
    }
}

/// Return status of an NSS function call.
///
/// Defined here:
/// <https://github.com/lattera/glibc/blob/895ef79e04a953cac1493863bcae29ad85657ee1/nss/nss.h#L30-L38>
#[derive(Debug, PartialEq, Eq)]
pub enum NssStatus {
    /// This service is temporarily unusable. For example, the given address
    /// buffer is too small or the backing DNS service is overloaded.
    TryAgain = -2,

    /// Plugin failure. For example, a bug was detected and the library
    /// decided to quit immediately.
    Unavailable,

    /// The query completed successfully without returning any matching hosts.
    /// Pairs with [`HostStatus::HostNotFound`].
    NotFound,

    /// Request succeeded. Caller should check the linked list of results.
    Success,
    //
    // Don't use `RETURN`? nss-mdns never does, and some brief searching
    // suggests plugins should not return this value.
    // Return,
}

/// The NSS Host lookup errno. Further explains the
/// standard C errno.
///
/// Defined here. Comments copied verbatim.
///
/// <https://github.com/lattera/glibc/blob/895ef79e04a953cac1493863bcae29ad85657ee1/resolv/netdb.h#L62-L75>
#[derive(Debug, PartialEq, Eq)]
pub enum HostStatus {
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
