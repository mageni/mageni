# OpenVAS Vulnerability Test
# $Id: deb_2812.nasl 14276 2019-03-18 14:43:56Z cfischer $
# Auto-generated from advisory DSA 2812-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH http://greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.892812");
  script_version("$Revision: 14276 $");
  script_cve_id("CVE-2013-4475", "CVE-2013-4408");
  script_name("Debian Security Advisory DSA 2812-1 (samba - several vulnerabilities)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:43:56 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2013-12-09 00:00:00 +0100 (Mon, 09 Dec 2013)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:C/I:C/A:C");

  script_xref(name:"URL", value:"http://www.debian.org/security/2013/dsa-2812.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(6|7)");
  script_tag(name:"affected", value:"samba on Debian Linux");
  script_tag(name:"solution", value:"For the oldstable distribution (squeeze), these problems have been fixed in
version 3.5.6~dfsg-3squeeze11.

For the stable distribution (wheezy), these problems have been fixed in
version 3.6.6-6+deb7u2.

For the unstable distribution (sid), these problems will be fixed soon.

We recommend that you upgrade your samba packages.");
  script_tag(name:"summary", value:"Two security issues were found in Samba, a SMB/CIFS file, print, and
login server:

CVE-2013-4408
It was discovered that multiple buffer overflows in the processing
of DCE-RPC packets may lead to the execution of arbitrary code.

CVE-2013-4475
Hemanth Thummala discovered that ACLs were not checked when opening
files with alternate data streams. This issue is only exploitable
if the VFS modules vfs_streams_depot and/or vfs_streams_xattr are
used.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"libpam-smbpass", ver:"3.5.6~dfsg-3squeeze11", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libsmbclient", ver:"3.5.6~dfsg-3squeeze11", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libsmbclient-dev", ver:"3.5.6~dfsg-3squeeze11", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libwbclient0", ver:"3.5.6~dfsg-3squeeze11", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"samba", ver:"3.5.6~dfsg-3squeeze11", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"samba-common", ver:"3.5.6~dfsg-3squeeze11", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"samba-common-bin", ver:"3.5.6~dfsg-3squeeze11", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"samba-dbg", ver:"3.5.6~dfsg-3squeeze11", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"samba-doc", ver:"3.5.6~dfsg-3squeeze11", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"samba-doc-pdf", ver:"3.5.6~dfsg-3squeeze11", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"samba-tools", ver:"3.5.6~dfsg-3squeeze11", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"smbclient", ver:"3.5.6~dfsg-3squeeze11", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"swat", ver:"3.5.6~dfsg-3squeeze11", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"winbind", ver:"3.5.6~dfsg-3squeeze11", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libnss-winbind", ver:"3.6.6-6+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libpam-smbpass", ver:"3.6.6-6+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libpam-winbind", ver:"3.6.6-6+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libsmbclient", ver:"3.6.6-6+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libsmbclient-dev", ver:"3.6.6-6+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libwbclient-dev", ver:"3.6.6-6+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libwbclient0", ver:"3.6.6-6+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"samba", ver:"3.6.6-6+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"samba-common", ver:"3.6.6-6+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"samba-common-bin", ver:"3.6.6-6+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"samba-dbg", ver:"3.6.6-6+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"samba-doc", ver:"3.6.6-6+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"samba-doc-pdf", ver:"3.6.6-6+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"samba-tools", ver:"3.6.6-6+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"smbclient", ver:"3.6.6-6+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"swat", ver:"3.6.6-6+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"winbind", ver:"3.6.6-6+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}