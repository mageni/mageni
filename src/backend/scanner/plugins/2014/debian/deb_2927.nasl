# OpenVAS Vulnerability Test
# Auto-generated from advisory DSA 2927-1 using nvtgen 1.0
# Script version: 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.702927");
  script_version("2021-11-23T15:20:34+0000");
  script_cve_id("CVE-2014-0209", "CVE-2014-0210", "CVE-2014-0211");
  script_name("Debian Security Advisory DSA 2927-1 (libxfont - security update)");
  script_tag(name:"last_modification", value:"2021-11-24 11:00:45 +0000 (Wed, 24 Nov 2021)");
  script_tag(name:"creation_date", value:"2014-05-13 00:00:00 +0200 (Tue, 13 May 2014)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_xref(name:"URL", value:"http://www.debian.org/security/2014/dsa-2927.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(6|7)");
  script_tag(name:"affected", value:"libxfont on Debian Linux");
  script_tag(name:"solution", value:"For the oldstable distribution (squeeze), these problems have been fixed in
version 1:1.4.1-5.

For the stable distribution (wheezy), these problems have been fixed in
version 1:1.4.5-4.

For the unstable distribution (sid), these problems have been fixed in
version 1:1.4.7-2.

We recommend that you upgrade your libxfont packages.");
  script_tag(name:"summary", value:"Ilja van Sprundel of IOActive discovered several security issues in the
X.Org libXfont library, which may allow a local, authenticated user to
attempt to raise privileges, or a remote attacker who can control the
font server to attempt to execute code with the privileges of the X
server.

CVE-2014-0209
Integer overflow of allocations in font metadata file parsing could
allow a local user who is already authenticated to the X server to
overwrite other memory in the heap.

CVE-2014-0210
libxfont does not validate length fields when parsing xfs protocol
replies allowing to write past the bounds of allocated memory when
storing the returned data from the font server.

CVE-2014-0211
Integer overflows calculating memory needs for xfs replies could
result in allocating too little memory and then writing the returned
data from the font server past the end of the allocated buffer.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"libxfont-dev", ver:"1:1.4.1-5", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libxfont1", ver:"1:1.4.1-5", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libxfont1-dbg", ver:"1:1.4.1-5", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libxfont-dev", ver:"1:1.4.5-4", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libxfont1", ver:"1:1.4.5-4", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libxfont1-dbg", ver:"1:1.4.5-4", rls:"DEB7")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}