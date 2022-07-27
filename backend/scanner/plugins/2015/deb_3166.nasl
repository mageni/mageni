# OpenVAS Vulnerability Test
# $Id: deb_3166.nasl 14278 2019-03-18 14:47:26Z cfischer $
# Auto-generated from advisory DSA 3166-1 using nvtgen 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.703166");
  script_version("$Revision: 14278 $");
  script_cve_id("CVE-2015-0247", "CVE-2015-1572");
  script_name("Debian Security Advisory DSA 3166-1 (e2fsprogs - security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:47:26 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2015-02-22 00:00:00 +0100 (Sun, 22 Feb 2015)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"http://www.debian.org/security/2015/dsa-3166.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");
  script_tag(name:"affected", value:"e2fsprogs on Debian Linux");
  script_tag(name:"solution", value:"For the stable distribution (wheezy),
these problems have been fixed in version 1.42.5-1.1+deb7u1.

For the upcoming stable (jessie) and unstable (sid) distributions,
these problems will be fixed soon.

We recommend that you upgrade your e2fsprogs packages.");
  script_tag(name:"summary", value:"Jose Duart of the Google Security Team
discovered a buffer overflow in e2fsprogs, a set of utilities for the ext2, ext3,
and ext4 file systems. This issue can possibly lead to arbitrary code execution if
a malicious device is plugged in, the system is configured to
automatically mount it, and the mounting process chooses to run fsck
on the device's malicious filesystem.

CVE-2015-0247
Buffer overflow in the ext2/ext3/ext4 file system open/close
routines.

CVE-2015-1572Incomplete fix for
CVE-2015-0247
.");
  script_tag(name:"vuldetect", value:"This check tests the installed software
version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"comerr-dev", ver:"1.42.5-1.1+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"e2fsck-static", ver:"1.42.5-1.1+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"e2fslibs:amd64", ver:"1.42.5-1.1+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"e2fslibs:i386", ver:"1.42.5-1.1+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"e2fslibs-dbg", ver:"1.42.5-1.1+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"e2fslibs-dev", ver:"1.42.5-1.1+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"e2fsprogs", ver:"1.42.5-1.1+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"e2fsprogs-dbg", ver:"1.42.5-1.1+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"e2fsprogs-udeb", ver:"1.42.5-1.1+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libcomerr2:amd64", ver:"1.42.5-1.1+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libcomerr2:i386", ver:"1.42.5-1.1+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libcomerr2-dbg", ver:"1.42.5-1.1+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libss2:amd64", ver:"1.42.5-1.1+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libss2:i386", ver:"1.42.5-1.1+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libss2-dbg", ver:"1.42.5-1.1+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ss-dev", ver:"1.42.5-1.1+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}