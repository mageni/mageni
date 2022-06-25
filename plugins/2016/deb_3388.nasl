# OpenVAS Vulnerability Test
# $Id: deb_3388.nasl 8154 2017-12-18 07:30:14Z teissa $
# Auto-generated from advisory DSA 3388-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH http://greenbone.net
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#


if(description)
{
    script_oid("1.3.6.1.4.1.25623.1.0.703388");
    script_version("$Revision: 8154 $");
    script_cve_id("CVE-2014-9750", "CVE-2014-9751", "CVE-2015-3405", "CVE-2015-5146",
                  "CVE-2015-5194", "CVE-2015-5195", "CVE-2015-5219", "CVE-2015-5300",
                  "CVE-2015-7691", "CVE-2015-7692", "CVE-2015-7701", "CVE-2015-7702",
                  "CVE-2015-7703", "CVE-2015-7704", "CVE-2015-7850", "CVE-2015-7852",
                  "CVE-2015-7855", "CVE-2015-7871");
    script_name("Debian Security Advisory DSA 3388-1 (ntp - security update)");
    script_tag(name: "last_modification", value: "$Date: 2017-12-18 08:30:14 +0100 (Mon, 18 Dec 2017) $");
    script_tag(name:"creation_date", value:"2016-05-06 15:29:25 +0530 (Fri, 06 May 2016)");
    script_tag(name:"cvss_base", value:"7.8");
    script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
    script_tag(name: "solution_type", value: "VendorFix");
    script_tag(name: "qod_type", value: "package");

    script_xref(name: "URL", value: "http://www.debian.org/security/2015/dsa-3388.html");


    script_category(ACT_GATHER_INFO);

    script_copyright("Copyright (c) 2016 Greenbone Networks GmbH http://greenbone.net");
    script_family("Debian Local Security Checks");
    script_dependencies("gather-package-list.nasl");
    script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages");
    script_tag(name: "affected",  value: "ntp on Debian Linux");
    script_tag(name: "insight",   value: "NTP, the Network Time Protocol,
is used to keep computer clocks accurate by synchronizing them over the Internet or
a local network, or by following an accurate hardware receiver that interprets GPS,
DCF-77, NIST or similar time signals.");
    script_tag(name: "solution",  value: "For the oldstable distribution (wheezy),
these problems have been fixed in version 1:4.2.6.p5+dfsg-2+deb7u6.

For the stable distribution (jessie), these problems have been fixed in
version 1:4.2.6.p5+dfsg-7+deb8u1.

For the testing distribution (stretch), these problems have been fixed
in version 1:4.2.8p4+dfsg-3.

For the unstable distribution (sid), these problems have been fixed in
version 1:4.2.8p4+dfsg-3.

We recommend that you upgrade your ntp packages.");
    script_tag(name: "summary",   value: "Several vulnerabilities were discovered
in the Network Time Protocol daemon and utility programs:

CVE-2015-5146 
A flaw was found in the way ntpd processed certain remote
configuration packets. An attacker could use a specially crafted
package to cause ntpd to crash if:

ntpd enabled remote configurationThe attacker had the knowledge of the configuration
password...The attacker had access to a computer entrusted to perform remote
configuration 
Note that remote configuration is disabled by default in NTP.

CVE-2015-5194 
It was found that ntpd could crash due to an uninitialized
variable when processing malformed logconfig configuration
commands.

CVE-2015-5195 
It was found that ntpd exits with a segmentation fault when a
statistics type that was not enabled during compilation (e.g.
timingstats) is referenced by the statistics or filegen
configuration command.

CVE-2015-5219 
It was discovered that sntp program would hang in an infinite loop
when a crafted NTP packet was received, related to the conversion
of the precision value in the packet to double.

CVE-2015-5300 
It was found that ntpd did not correctly implement the -g option:

Normally, ntpd exits with a message to the system log if the offset
exceeds the panic threshold, which is 1000 s by default. This
option allows the time to be set to any value without restriction;
however, this can happen only once. If the threshold is exceeded
after that, ntpd will exit with a message to the system log. This
option can be used with the -q and -x options.

ntpd could actually step the clock multiple times by more than the
panic threshold if its clock discipline doesn't have enough time to
reach the sync state and stay there for at least one update. If a
man-in-the-middle attacker can control the NTP traffic since ntpd
was started (or maybe up to 15-30 minutes after that), they can
prevent the client from reaching the sync state and force it to step
its clock by any amount any number of times, which can be used by
attackers to expire certificates, etc.

This is contrary to what the documentation says. Normally, the
assumption is that an MITM attacker can step the clock more than the
panic threshold only once when ntpd starts and to make a larger
adjustment the attacker has to divide it into multiple smaller
steps, each taking 15 minutes, which is slow.

CVE-2015-7691,
CVE-2015-7692,
CVE-2015-7702It was found that the fix for
CVE-2014-9750 

was incomplete: three issues were found in the value length checks in
ntp_crypto.c, where a packet with particular autokey operations that
contained malicious data was not always being completely validated. Receipt
of these packets can cause ntpd to crash.

CVE-2015-7701 
A memory leak flaw was found in ntpd's CRYPTO_ASSOC. If ntpd is
configured to use autokey authentication, an attacker could send
packets to ntpd that would, after several days of ongoing attack,
cause it to run out of memory.

CVE-2015-7703 
Miroslav Lichvar of Red Hat found that the :config command can be
used to set the pidfile and driftfile paths without any
restrictions. A remote attacker could use this flaw to overwrite a
file on the file system with a file containing the pid of the ntpd
process (immediately) or the current estimated drift of the system
clock (in hourly intervals). For example:

ntpq -c ':config pidfile /tmp/ntp.pid' ntpq -c ':config driftfile /tmp/ntp.drift' 
In Debian ntpd is configured to drop root privileges, which limits
the impact of this issue.

CVE-2015-7704 
If ntpd as an NTP client receives a Kiss-of-Death (KoD) packet
from the server to reduce its polling rate, it doesn't check if the
originate timestamp in the reply matches the transmit timestamp from
its request. An off-path attacker can send a crafted KoD packet to
the client, which will increase the client's polling interval to a
large value and effectively disable synchronization with the server.

CVE-2015-7850 
An exploitable denial of service vulnerability exists in the remote
configuration functionality of the Network Time Protocol. A
specially crafted configuration file could cause an endless loop
resulting in a denial of service. An attacker could provide a
malicious configuration file to trigger this vulnerability.

CVE-2015-7852 
A potential off by one vulnerability exists in the cookedprint
functionality of ntpq. A specially crafted buffer could cause a
buffer overflow potentially resulting in null byte being written out
of bounds.

CVE-2015-7855 
It was found that NTP's decodenetnum() would abort with an assertion
failure when processing a mode 6 or mode 7 packet containing an
unusually long data value where a network address was expected. This
could allow an authenticated attacker to crash ntpd.

CVE-2015-7871 
An error handling logic error exists within ntpd that manifests due
to improper error condition handling associated with certain
crypto-NAK packets. An unauthenticated, off-path attacker can force
ntpd processes on targeted servers to peer with time sources of the
attacker's choosing by transmitting symmetric active crypto-NAK
packets to ntpd. This attack bypasses the authentication typically
required to establish a peer association and allows an attacker to
make arbitrary changes to system time.");
    script_tag(name: "vuldetect", value: "This check tests the installed
software version using the apt package manager.");
    exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if ((res = isdpkgvuln(pkg:"ntp", ver:"1:4.2.6.p5+dfsg-7+deb8u1", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ntp-doc", ver:"1:4.2.6.p5+dfsg-7+deb8u1", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ntpdate", ver:"1:4.2.6.p5+dfsg-7+deb8u1", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ntp", ver:"1:4.2.8p4+dfsg-3", rls_regex:"DEB9.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ntp-doc", ver:"1:4.2.8p4+dfsg-3", rls_regex:"DEB9.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ntpdate", ver:"1:4.2.8p4+dfsg-3", rls_regex:"DEB9.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ntp", ver:"1:4.2.6.p5+dfsg-2+deb7u6", rls_regex:"DEB7.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ntp-doc", ver:"1:4.2.6.p5+dfsg-2+deb7u6", rls_regex:"DEB7.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ntpdate", ver:"1:4.2.6.p5+dfsg-2+deb7u6", rls_regex:"DEB7.[0-9]+")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
