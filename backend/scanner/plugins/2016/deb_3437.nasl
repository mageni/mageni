# OpenVAS Vulnerability Test
# $Id: deb_3437.nasl 14279 2019-03-18 14:48:34Z cfischer $
# Auto-generated from advisory DSA 3437-1 using nvtgen 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.703437");
  script_version("$Revision: 14279 $");
  script_cve_id("CVE-2015-7575");
  script_name("Debian Security Advisory DSA 3437-1 (gnutls26 - security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:48:34 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2016-01-09 00:00:00 +0100 (Sat, 09 Jan 2016)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"http://www.debian.org/security/2016/dsa-3437.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2016 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");
  script_tag(name:"affected", value:"gnutls26 on Debian Linux");
  script_tag(name:"solution", value:"For the oldstable distribution
(wheezy), this problem has been fixed in version 2.12.20-8+deb7u5.

We recommend that you upgrade your gnutls26 packages.");
  script_tag(name:"summary", value:"Karthikeyan Bhargavan and Gaetan
Leurent at INRIA discovered a flaw in the TLS 1.2 protocol which could allow
the MD5 hash function to be used for signing ServerKeyExchange and Client
Authentication packets during a TLS handshake. A man-in-the-middle attacker
could exploit this flaw to conduct collision attacks to impersonate a TLS
server or an authenticated TLS client.");
  script_tag(name:"vuldetect", value:"This check tests the installed
software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"gnutls-bin", ver:"2.12.20-8+deb7u5", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"gnutls26-doc", ver:"2.12.20-8+deb7u5", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"guile-gnutls:amd64", ver:"2.12.20-8+deb7u5", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"guile-gnutls:i386", ver:"2.12.20-8+deb7u5", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libgnutls-dev", ver:"2.12.20-8+deb7u5", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libgnutls-openssl27:amd64", ver:"2.12.20-8+deb7u5", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libgnutls-openssl27:i386", ver:"2.12.20-8+deb7u5", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libgnutls26:amd64", ver:"2.12.20-8+deb7u5", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libgnutls26:i386", ver:"2.12.20-8+deb7u5", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libgnutls26-dbg", ver:"2.12.20-8+deb7u5", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libgnutlsxx27:amd64", ver:"2.12.20-8+deb7u5", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libgnutlsxx27:i386", ver:"2.12.20-8+deb7u5", rls:"DEB7")) != NULL) {
  report += res;
}


if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}