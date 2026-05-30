//! This NSS module resolves the hostname `example` to IPv6 localhost
//! with a TTL of 0.
//!
//! This specific module can be used like so:
//! - Build it: `cargo build --example nss_example --release`
//! - Rename it to match the NSS ABI version and copy to
//!   your platform's canonical location: (example is fedora)
//!   `cp target/release/examples/libnss_example.so /usr/lib64/libnss_example.so.2`
//! - Update your /etc/nsswitch.conf accordingly and`ping example` for fun and profit.

use core::net::Ipv6Addr;

use libnss_host4::Addr;
use libnss_host4::HostResolver;
use libnss_host4::err::NssErr;
use libnss_host4::impl_gethostbyname4_r;

struct ExampleResolver;
impl_gethostbyname4_r!(example, ExampleResolver);

impl HostResolver for ExampleResolver {
    fn resolve_host(hostname: &str) -> Result<impl IntoIterator<Item = Addr>, NssErr> {
        if hostname.eq_ignore_ascii_case("example") {
            Ok([Addr {
                ip: Ipv6Addr::LOCALHOST.into(),
                scope_id: 0,
            }])
        } else {
            Err(NssErr::NO_RESULT)
        }
    }

    fn set_ttlp(hostname: &str) -> Option<i32> {
        hostname.eq_ignore_ascii_case("example").then_some(0)
    }
}
