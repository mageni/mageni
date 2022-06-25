# OpenVAS Vulnerability Test
# $Id: deb_3436.nasl 14279 2019-03-18 14:48:34Z cfischer $
# Auto-generated from advisory DSA 3436-1 using nvtgen 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.703436");
  script_version("$Revision: 14279 $");
  script_cve_id("CVE-2015-7575");
  script_name("Debian Security Advisory DSA 3436-1 (openssl - security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:48:34 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2016-01-08 00:00:00 +0100 (Fri, 08 Jan 2016)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"http://www.debian.org/security/2016/dsa-3436.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2016 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");
  script_tag(name:"affected", value:"openssl on Debian Linux");
  script_tag(name:"solution", value:"For the oldstable distribution (wheezy),
this problem has been fixed in version 1.0.1e-2+deb7u19.

For the stable distribution (jessie), the testing distribution (stretch)
and the unstable distribution (sid), this issue was already addressed in
version 1.0.1f-1.

We recommend that you upgrade your openssl packages.");
  script_tag(name:"summary", value:"Karthikeyan Bhargavan and Gaetan Leurent
at INRIA discovered a flaw in the TLS 1.2 protocol which could allow the MD5 hash
function to be used for signing ServerKeyExchange and Client Authentication packets
during a TLS handshake. A man-in-the-middle attacker could exploit this flaw to
conduct collision attacks to impersonate a TLS server or an
authenticated TLS client.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"libssl-dev", ver:"1.0.1e-2+deb7u19", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libssl-doc", ver:"1.0.1e-2+deb7u19", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libssl1.0.0:amd64", ver:"1.0.1e-2+deb7u19", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libssl1.0.0:i386", ver:"1.0.1e-2+deb7u19", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libssl1.0.0-dbg:amd64", ver:"1.0.1e-2+deb7u19", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libssl1.0.0-dbg:i386", ver:"1.0.1e-2+deb7u19", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openssl", ver:"1.0.1e-2+deb7u19", rls:"DEB7")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}