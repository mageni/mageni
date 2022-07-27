# OpenVAS Vulnerability Test
# $Id: deb_3451.nasl 14279 2019-03-18 14:48:34Z cfischer $
# Auto-generated from advisory DSA 3451-1 using nvtgen 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.703451");
  script_version("$Revision: 14279 $");
  script_cve_id("CVE-2016-1233");
  script_name("Debian Security Advisory DSA 3451-1 (fuse - security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:48:34 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2016-01-20 00:00:00 +0100 (Wed, 20 Jan 2016)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"http://www.debian.org/security/2016/dsa-3451.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2016 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(9|8)");
  script_tag(name:"affected", value:"fuse on Debian Linux");
  script_tag(name:"solution", value:"For the oldstable distribution (wheezy),
the fuse package is not affected.

For the stable distribution (jessie), this problem has been fixed in
version 2.9.3-15+deb8u2.

For the testing distribution (stretch), this problem has been fixed
in version 2.9.5-1.

For the unstable distribution (sid), this problem has been fixed in
version 2.9.5-1.

We recommend that you upgrade your fuse packages.");
  script_tag(name:"summary", value:"Jann Horn discovered a vulnerability in
the fuse (Filesystem in Userspace) package in Debian. The fuse package ships an
udev rule adjusting permissions on the related /dev/cuse character device, making
it world writable.

This permits a local, unprivileged attacker to create an
arbitrarily-named character device in /dev and modify the memory of any
process that opens it and performs an ioctl on it.

This in turn might allow a local, unprivileged attacker to escalate to
root privileges.");
  script_tag(name:"vuldetect", value:"This check tests the installed software
version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"fuse", ver:"2.9.5-1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"fuse-dbg", ver:"2.9.5-1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"fuse-udeb", ver:"2.9.5-1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libfuse-dev", ver:"2.9.5-1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libfuse2:i386", ver:"2.9.5-1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libfuse2:amd64", ver:"2.9.5-1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libfuse2-udeb", ver:"2.9.5-1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"fuse", ver:"2.9.3-15+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"fuse-dbg", ver:"2.9.3-15+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libfuse-dev", ver:"2.9.3-15+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libfuse2:amd64", ver:"2.9.3-15+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libfuse2:i386", ver:"2.9.3-15+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}