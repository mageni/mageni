# OpenVAS Vulnerability Test
# $Id: deb_3125.nasl 14278 2019-03-18 14:47:26Z cfischer $
# Auto-generated from advisory DSA 3125-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.703125");
  script_version("$Revision: 14278 $");
  script_cve_id("CVE-2014-3569", "CVE-2014-3570", "CVE-2014-3571", "CVE-2014-3572",
                  "CVE-2014-8275", "CVE-2015-0204", "CVE-2015-0205", "CVE-2015-0206");
  script_name("Debian Security Advisory DSA 3125-1 (openssl - security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:47:26 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2015-01-11 00:00:00 +0100 (Sun, 11 Jan 2015)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.debian.org/security/2015/dsa-3125.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");
  script_tag(name:"affected", value:"openssl on Debian Linux");
  script_tag(name:"solution", value:"For the stable distribution (wheezy),
these problems have been fixed in version 1.0.1e-2+deb7u14.

For the upcoming stable distribution (jessie), these problems will be
fixed soon.

For the unstable distribution (sid), these problems have been fixed in
version 1.0.1k-1.

We recommend that you upgrade your openssl packages.");
  script_tag(name:"summary", value:"Multiple vulnerabilities have been
discovered in OpenSSL, a Secure Sockets Layer toolkit. The Common Vulnerabilities
and Exposures project identifies the following issues:

CVE-2014-3569
Frank Schmirler reported that the ssl23_get_client_hello function in
OpenSSL does not properly handle attempts to use unsupported
protocols. When OpenSSL is built with the no-ssl3 option and a SSL
v3 ClientHello is received, the ssl method would be set to NULL which
could later result in a NULL pointer dereference and daemon crash.

CVE-2014-3570
Pieter Wuille of Blockstream reported that the bignum squaring
(BN_sqr) may produce incorrect results on some platforms, which
might make it easier for remote attackers to defeat cryptographic
protection mechanisms.

CVE-2014-3571
Markus Stenberg of Cisco Systems, Inc. reported that a carefully
crafted DTLS message can cause a segmentation fault in OpenSSL due
to a NULL pointer dereference. A remote attacker could use this flaw
to mount a denial of service attack.

CVE-2014-3572
Karthikeyan Bhargavan of the PROSECCO team at INRIA reported that an
OpenSSL client would accept a handshake using an ephemeral ECDH
ciphersuite if the server key exchange message is omitted. This
allows remote SSL servers to conduct ECDHE-to-ECDH downgrade attacks
and trigger a loss of forward secrecy.

CVE-2014-8275
Antti Karjalainen and Tuomo Untinen of the Codenomicon CROSS project
and Konrad Kraszewski of Google reported various certificate
fingerprint issues, which allow remote attackers to defeat a
fingerprint-based certificate-blacklist protection mechanism.

CVE-2015-0204
Karthikeyan Bhargavan of the PROSECCO team at INRIA reported that
an OpenSSL client will accept the use of an ephemeral RSA key in a
non-export RSA key exchange ciphersuite, violating the TLS
standard. This allows remote SSL servers to downgrade the security
of the session.

CVE-2015-0205
Karthikeyan Bhargavan of the PROSECCO team at INRIA reported that an
OpenSSL server will accept a DH certificate for client
authentication without the certificate verify message. This flaw
effectively allows a client to authenticate without the use of a
private key via crafted TLS handshake protocol traffic to a server
that recognizes a certification authority with DH support.

CVE-2015-0206
Chris Mueller discovered a memory leak in the dtls1_buffer_record
function. A remote attacker could exploit this flaw to mount a
denial of service through memory exhaustion by repeatedly sending
specially crafted DTLS records.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"libssl-dev", ver:"1.0.1e-2+deb7u14", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libssl-doc", ver:"1.0.1e-2+deb7u14", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libssl1.0.0", ver:"1.0.1e-2+deb7u14", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libssl1.0.0-dbg", ver:"1.0.1e-2+deb7u14", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openssl", ver:"1.0.1e-2+deb7u14", rls:"DEB7")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}