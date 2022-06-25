# OpenVAS Vulnerability Test
# $Id: deb_3413.nasl 14278 2019-03-18 14:47:26Z cfischer $
# Auto-generated from advisory DSA 3413-1 using nvtgen 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.703413");
  script_version("$Revision: 14278 $");
  script_cve_id("CVE-2015-3194", "CVE-2015-3195", "CVE-2015-3196");
  script_name("Debian Security Advisory DSA 3413-1 (openssl - security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:47:26 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2015-12-04 00:00:00 +0100 (Fri, 04 Dec 2015)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"http://www.debian.org/security/2015/dsa-3413.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(7|8)");
  script_tag(name:"affected", value:"openssl on Debian Linux");
  script_tag(name:"solution", value:"For the oldstable distribution (wheezy), these
problems have been fixed in version 1.0.1e-2+deb7u18.

For the stable distribution (jessie), these problems have been fixed in
version 1.0.1k-3+deb8u2.

For the unstable distribution (sid), these problems have been fixed in
version 1.0.2e-1 or earlier.

We recommend that you upgrade your openssl packages.");
  script_tag(name:"summary", value:"Multiple vulnerabilities have been
discovered in OpenSSL, a Secure Sockets Layer toolkit. The Common Vulnerabilities
and Exposures project identifies the following issues:

CVE-2015-3194
Loic Jonas Etienne of Qnective AG discovered that the signature
verification routines will crash with a NULL pointer dereference if
presented with an ASN.1 signature using the RSA PSS algorithm and
absent mask generation function parameter. A remote attacker can
exploit this flaw to crash any certificate verification operation
and mount a denial of service attack.

CVE-2015-3195
Adam Langley of Google/BoringSSL discovered that OpenSSL will leak
memory when presented with a malformed X509_ATTRIBUTE structure.

CVE-2015-3196
A race condition flaw in the handling of PSK identify hints was
discovered, potentially leading to a double free of the identify
hint data.");
  script_tag(name:"vuldetect", value:"This check tests the installed
software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"libssl-dev", ver:"1.0.1e-2+deb7u18", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libssl-doc", ver:"1.0.1e-2+deb7u18", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libssl1.0.0:amd64", ver:"1.0.1e-2+deb7u18", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libssl1.0.0:i386", ver:"1.0.1e-2+deb7u18", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libssl1.0.0-dbg:amd64", ver:"1.0.1e-2+deb7u18", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libssl1.0.0-dbg:i386", ver:"1.0.1e-2+deb7u18", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openssl", ver:"1.0.1e-2+deb7u18", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libssl-dev", ver:"1.0.1k-3+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libssl-doc", ver:"1.0.1k-3+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libssl1.0.0:amd64", ver:"1.0.1k-3+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libssl1.0.0:i386", ver:"1.0.1k-3+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libssl1.0.0-dbg:amd64", ver:"1.0.1k-3+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libssl1.0.0-dbg:i386", ver:"1.0.1k-3+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openssl", ver:"1.0.1k-3+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}