###############################################################################
# OpenVAS Vulnerability Test
# $Id: deb_dla_1392.nasl 14281 2019-03-18 14:53:48Z cfischer $
#
# Auto-generated from advisory DLA 1392-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH http://greenbone.net
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891392");
  script_version("$Revision: 14281 $");
  script_cve_id("CVE-2018-1093", "CVE-2018-10940", "CVE-2018-1130", "CVE-2018-8897");
  script_name("Debian LTS Advisory ([SECURITY] [DLA 1392-1] linux security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:53:48 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2018-06-04 00:00:00 +0200 (Mon, 04 Jun 2018)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2018/06/msg00000.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");
  script_tag(name:"affected", value:"linux on Debian Linux");
  script_tag(name:"solution", value:"For Debian 7 'Wheezy', these problems have been fixed in version
3.2.102-1. This version also includes bug fixes from upstream version
3.2.102, including a fix for a regression in the SCTP implementation
in version 3.2.101.

We recommend that you upgrade your linux packages.");
  script_tag(name:"summary", value:"Several vulnerabilities have been discovered in the Linux kernel that
may lead to a denial of service.

CVE-2018-1093

Wen Xu reported that a crafted ext4 filesystem image could trigger
an out-of-bounds read in the ext4_valid_block_bitmap() function. A
local user able to mount arbitrary filesystems could use this for
denial of service.

CVE-2018-1130

The syzbot software found that the DCCP implementation of
sendmsg() does not check the socket state, potentially leading
to a null pointer dereference. A local user could use this to
cause a denial of service (crash).

CVE-2018-8897

Nick Peterson of Everdox Tech LLC discovered that #DB exceptions
that are deferred by MOV SS or POP SS are not properly handled,
allowing an unprivileged user to crash the kernel and cause a
denial of service.

CVE-2018-10940

Dan Carpenter reported that the cdrom driver does not correctly
validate the parameter to the CDROM_MEDIA_CHANGED ioctl. A user
with access to a cdrom device could use this to cause a denial of
service (crash).");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"linux-doc-3.2", ver:"3.2.102-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-486", ver:"3.2.102-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-686-pae", ver:"3.2.102-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-all", ver:"3.2.102-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-all-amd64", ver:"3.2.102-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-all-armel", ver:"3.2.102-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-all-armhf", ver:"3.2.102-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-all-i386", ver:"3.2.102-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-amd64", ver:"3.2.102-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-common", ver:"3.2.102-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-common-rt", ver:"3.2.102-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-iop32x", ver:"3.2.102-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-ixp4xx", ver:"3.2.102-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-kirkwood", ver:"3.2.102-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-mv78xx0", ver:"3.2.102-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-mx5", ver:"3.2.102-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-omap", ver:"3.2.102-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-orion5x", ver:"3.2.102-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-rt-686-pae", ver:"3.2.102-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-rt-amd64", ver:"3.2.102-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-versatile", ver:"3.2.102-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-vexpress", ver:"3.2.102-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-5-486", ver:"3.2.102-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-5-686-pae", ver:"3.2.102-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-5-all", ver:"3.2.102-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-5-all-amd64", ver:"3.2.102-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-5-all-armel", ver:"3.2.102-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-5-all-armhf", ver:"3.2.102-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-5-all-i386", ver:"3.2.102-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-5-amd64", ver:"3.2.102-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-5-common", ver:"3.2.102-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-5-common-rt", ver:"3.2.102-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-5-iop32x", ver:"3.2.102-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-5-ixp4xx", ver:"3.2.102-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-5-kirkwood", ver:"3.2.102-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-5-mv78xx0", ver:"3.2.102-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-5-mx5", ver:"3.2.102-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-5-omap", ver:"3.2.102-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-5-orion5x", ver:"3.2.102-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-5-rt-686-pae", ver:"3.2.102-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-5-rt-amd64", ver:"3.2.102-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-5-versatile", ver:"3.2.102-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-5-vexpress", ver:"3.2.102-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-6-486", ver:"3.2.102-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-6-686-pae", ver:"3.2.102-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-6-all", ver:"3.2.102-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-6-all-amd64", ver:"3.2.102-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-6-all-armel", ver:"3.2.102-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-6-all-armhf", ver:"3.2.102-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-6-all-i386", ver:"3.2.102-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-6-amd64", ver:"3.2.102-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-6-common", ver:"3.2.102-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-6-common-rt", ver:"3.2.102-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-6-iop32x", ver:"3.2.102-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-6-ixp4xx", ver:"3.2.102-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-6-kirkwood", ver:"3.2.102-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-6-mv78xx0", ver:"3.2.102-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-6-mx5", ver:"3.2.102-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-6-omap", ver:"3.2.102-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-6-orion5x", ver:"3.2.102-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-6-rt-686-pae", ver:"3.2.102-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-6-rt-amd64", ver:"3.2.102-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-6-versatile", ver:"3.2.102-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-6-vexpress", ver:"3.2.102-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-486", ver:"3.2.102-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-686-pae", ver:"3.2.102-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-686-pae-dbg", ver:"3.2.102-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-amd64", ver:"3.2.102-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-amd64-dbg", ver:"3.2.102-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-iop32x", ver:"3.2.102-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-ixp4xx", ver:"3.2.102-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-kirkwood", ver:"3.2.102-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-mv78xx0", ver:"3.2.102-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-mx5", ver:"3.2.102-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-omap", ver:"3.2.102-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-orion5x", ver:"3.2.102-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-rt-686-pae", ver:"3.2.102-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-rt-686-pae-dbg", ver:"3.2.102-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-rt-amd64", ver:"3.2.102-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-rt-amd64-dbg", ver:"3.2.102-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-versatile", ver:"3.2.102-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-vexpress", ver:"3.2.102-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-5-486", ver:"3.2.102-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-5-686-pae", ver:"3.2.102-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-5-686-pae-dbg", ver:"3.2.102-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-5-amd64", ver:"3.2.102-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-5-amd64-dbg", ver:"3.2.102-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-5-iop32x", ver:"3.2.102-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-5-ixp4xx", ver:"3.2.102-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-5-kirkwood", ver:"3.2.102-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-5-mv78xx0", ver:"3.2.102-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-5-mx5", ver:"3.2.102-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-5-omap", ver:"3.2.102-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-5-orion5x", ver:"3.2.102-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-5-rt-686-pae", ver:"3.2.102-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-5-rt-686-pae-dbg", ver:"3.2.102-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-5-rt-amd64", ver:"3.2.102-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-5-rt-amd64-dbg", ver:"3.2.102-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-5-versatile", ver:"3.2.102-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-5-vexpress", ver:"3.2.102-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-6-486", ver:"3.2.102-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-6-686-pae", ver:"3.2.102-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-6-686-pae-dbg", ver:"3.2.102-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-6-amd64", ver:"3.2.102-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-6-amd64-dbg", ver:"3.2.102-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-6-iop32x", ver:"3.2.102-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-6-ixp4xx", ver:"3.2.102-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-6-kirkwood", ver:"3.2.102-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-6-mv78xx0", ver:"3.2.102-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-6-mx5", ver:"3.2.102-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-6-omap", ver:"3.2.102-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-6-orion5x", ver:"3.2.102-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-6-rt-686-pae", ver:"3.2.102-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-6-rt-686-pae-dbg", ver:"3.2.102-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-6-rt-amd64", ver:"3.2.102-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-6-rt-amd64-dbg", ver:"3.2.102-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-6-versatile", ver:"3.2.102-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-6-vexpress", ver:"3.2.102-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-libc-dev", ver:"3.2.102-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-manual-3.2", ver:"3.2.102-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-source-3.2", ver:"3.2.102-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-support-3.2.0-4", ver:"3.2.102-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-support-3.2.0-5", ver:"3.2.102-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-support-3.2.0-6", ver:"3.2.102-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xen-linux-system-3.2.0-4-686-pae", ver:"3.2.102-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xen-linux-system-3.2.0-4-amd64", ver:"3.2.102-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xen-linux-system-3.2.0-5-686-pae", ver:"3.2.102-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xen-linux-system-3.2.0-5-amd64", ver:"3.2.102-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xen-linux-system-3.2.0-6-686-pae", ver:"3.2.102-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xen-linux-system-3.2.0-6-amd64", ver:"3.2.102-1", rls:"DEB7")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}