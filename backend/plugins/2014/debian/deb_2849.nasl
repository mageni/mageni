# OpenVAS Vulnerability Test
# Auto-generated from advisory DSA 2849-1 using nvtgen 1.0
# Script version: 1.3
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
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
  script_oid("1.3.6.1.4.1.25623.1.0.702849");
  script_version("2021-11-23T15:20:34+0000");
  script_cve_id("CVE-2014-0015");
  script_name("Debian Security Advisory DSA 2849-1 (curl - information disclosure)");
  script_tag(name:"last_modification", value:"2021-11-24 11:00:45 +0000 (Wed, 24 Nov 2021)");
  script_tag(name:"creation_date", value:"2014-01-31 00:00:00 +0100 (Fri, 31 Jan 2014)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:N");

  script_xref(name:"URL", value:"http://www.debian.org/security/2014/dsa-2849.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(6|7)");
  script_tag(name:"affected", value:"curl on Debian Linux");
  script_tag(name:"solution", value:"For the oldstable distribution (squeeze), this problem has been fixed in
version 7.21.0-2.1+squeeze7.

For the stable distribution (wheezy), this problem has been fixed in
version 7.26.0-1+wheezy8.

For the unstable distribution (sid), this problem has been fixed in
version 7.35.0-1.

We recommend that you upgrade your curl packages.");
  script_tag(name:"summary", value:"Paras Sethia discovered that libcurl, a client-side URL transfer
library, would sometimes mix up multiple HTTP and HTTPS connections
with NTLM authentication to the same server, sending requests for one
user over the connection authenticated as a different user.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"curl", ver:"7.21.0-2.1+squeeze7", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libcurl3", ver:"7.21.0-2.1+squeeze7", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libcurl3-dbg", ver:"7.21.0-2.1+squeeze7", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libcurl3-gnutls", ver:"7.21.0-2.1+squeeze7", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libcurl4-gnutls-dev", ver:"7.21.0-2.1+squeeze7", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libcurl4-openssl-dev", ver:"7.21.0-2.1+squeeze7", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"curl", ver:"7.26.0-1+wheezy8", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libcurl3", ver:"7.26.0-1+wheezy8", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libcurl3-dbg", ver:"7.26.0-1+wheezy8", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libcurl3-gnutls", ver:"7.26.0-1+wheezy8", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libcurl3-nss", ver:"7.26.0-1+wheezy8", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libcurl4-gnutls-dev", ver:"7.26.0-1+wheezy8", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libcurl4-nss-dev", ver:"7.26.0-1+wheezy8", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libcurl4-openssl-dev", ver:"7.26.0-1+wheezy8", rls:"DEB7")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}