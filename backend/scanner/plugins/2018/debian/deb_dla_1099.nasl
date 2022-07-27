###############################################################################
# OpenVAS Vulnerability Test
# $Id: deb_dla_1099.nasl 14281 2019-03-18 14:53:48Z cfischer $
#
# Auto-generated from advisory DLA 1099-1 using nvtgen 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.891099");
  script_version("$Revision: 14281 $");
  script_cve_id("CVE-2017-1000111", "CVE-2017-1000251", "CVE-2017-1000363", "CVE-2017-1000365", "CVE-2017-1000380", "CVE-2017-10661", "CVE-2017-10911", "CVE-2017-11176", "CVE-2017-11600", "CVE-2017-12134", "CVE-2017-12153", "CVE-2017-12154", "CVE-2017-14106", "CVE-2017-14140", "CVE-2017-14156", "CVE-2017-14340", "CVE-2017-14489", "CVE-2017-7482", "CVE-2017-7542", "CVE-2017-7889");
  script_name("Debian LTS Advisory ([SECURITY] [DLA 1099-1] linux security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:53:48 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2018-02-07 00:00:00 +0100 (Wed, 07 Feb 2018)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2017/09/msg00017.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");
  script_tag(name:"affected", value:"linux on Debian Linux");
  script_tag(name:"solution", value:"For Debian 7 'Wheezy', these problems have been fixed in version
3.2.93-1. This version also includes bug fixes from upstream versions
up to and including 3.2.93.

For Debian 8 'Jessie', these problems have been fixed in version
3.16.43-2+deb8u4 or were fixed in an earlier version.

For Debian 9 'Stretch', these problems have been fixed in version
4.9.30-2+deb9u4 or were fixed in an earlier version.

We recommend that you upgrade your linux packages.");
  script_tag(name:"summary", value:"Several vulnerabilities have been discovered in the Linux kernel that
may lead to a privilege escalation, denial of service or information
leaks.

CVE-2017-7482

Shi Lei discovered that RxRPC Kerberos 5 ticket handling code does
not properly verify metadata, leading to information disclosure,
denial of service or potentially execution of arbitrary code.

CVE-2017-7542

An integer overflow vulnerability in the ip6_find_1stfragopt()
function was found allowing a local attacker with privileges to open
raw sockets to cause a denial of service.

CVE-2017-7889

Tommi Rantala and Brad Spengler reported that the mm subsystem does
not properly enforce the CONFIG_STRICT_DEVMEM protection mechanism,
allowing a local attacker with access to /dev/mem to obtain
sensitive information or potentially execute arbitrary code.

Description truncated. Please see the references for more information.

For Debian 7 'Wheezy', these problems have been fixed in version
3.2.93-1. This version also includes bug fixes from upstream versions
up to and including 3.2.93.

For Debian 8 'Jessie', these problems have been fixed in version
3.16.43-2+deb8u4 or were fixed in an earlier version.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"linux-doc-3.2", ver:"3.2.93-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-486", ver:"3.2.93-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-686-pae", ver:"3.2.93-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-all", ver:"3.2.93-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-all-amd64", ver:"3.2.93-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-all-armel", ver:"3.2.93-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-all-armhf", ver:"3.2.93-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-all-i386", ver:"3.2.93-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-amd64", ver:"3.2.93-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-common", ver:"3.2.93-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-common-rt", ver:"3.2.93-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-iop32x", ver:"3.2.93-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-ixp4xx", ver:"3.2.93-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-kirkwood", ver:"3.2.93-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-mv78xx0", ver:"3.2.93-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-mx5", ver:"3.2.93-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-omap", ver:"3.2.93-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-orion5x", ver:"3.2.93-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-rt-686-pae", ver:"3.2.93-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-rt-amd64", ver:"3.2.93-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-versatile", ver:"3.2.93-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-vexpress", ver:"3.2.93-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-5-486", ver:"3.2.93-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-5-686-pae", ver:"3.2.93-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-5-all", ver:"3.2.93-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-5-all-amd64", ver:"3.2.93-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-5-all-armel", ver:"3.2.93-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-5-all-armhf", ver:"3.2.93-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-5-all-i386", ver:"3.2.93-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-5-amd64", ver:"3.2.93-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-5-common", ver:"3.2.93-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-5-common-rt", ver:"3.2.93-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-5-iop32x", ver:"3.2.93-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-5-ixp4xx", ver:"3.2.93-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-5-kirkwood", ver:"3.2.93-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-5-mv78xx0", ver:"3.2.93-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-5-mx5", ver:"3.2.93-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-5-omap", ver:"3.2.93-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-5-orion5x", ver:"3.2.93-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-5-rt-686-pae", ver:"3.2.93-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-5-rt-amd64", ver:"3.2.93-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-5-versatile", ver:"3.2.93-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-5-vexpress", ver:"3.2.93-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-486", ver:"3.2.93-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-686-pae", ver:"3.2.93-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-686-pae-dbg", ver:"3.2.93-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-amd64", ver:"3.2.93-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-amd64-dbg", ver:"3.2.93-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-iop32x", ver:"3.2.93-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-ixp4xx", ver:"3.2.93-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-kirkwood", ver:"3.2.93-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-mv78xx0", ver:"3.2.93-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-mx5", ver:"3.2.93-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-omap", ver:"3.2.93-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-orion5x", ver:"3.2.93-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-rt-686-pae", ver:"3.2.93-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-rt-686-pae-dbg", ver:"3.2.93-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-rt-amd64", ver:"3.2.93-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-rt-amd64-dbg", ver:"3.2.93-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-versatile", ver:"3.2.93-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-vexpress", ver:"3.2.93-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-5-486", ver:"3.2.93-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-5-686-pae", ver:"3.2.93-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-5-686-pae-dbg", ver:"3.2.93-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-5-amd64", ver:"3.2.93-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-5-amd64-dbg", ver:"3.2.93-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-5-iop32x", ver:"3.2.93-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-5-ixp4xx", ver:"3.2.93-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-5-kirkwood", ver:"3.2.93-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-5-mv78xx0", ver:"3.2.93-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-5-mx5", ver:"3.2.93-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-5-omap", ver:"3.2.93-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-5-orion5x", ver:"3.2.93-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-5-rt-686-pae", ver:"3.2.93-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-5-rt-686-pae-dbg", ver:"3.2.93-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-5-rt-amd64", ver:"3.2.93-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-5-rt-amd64-dbg", ver:"3.2.93-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-5-versatile", ver:"3.2.93-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-5-vexpress", ver:"3.2.93-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-libc-dev", ver:"3.2.93-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-manual-3.2", ver:"3.2.93-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-source-3.2", ver:"3.2.93-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-support-3.2.0-4", ver:"3.2.93-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-support-3.2.0-5", ver:"3.2.93-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xen-linux-system-3.2.0-4-686-pae", ver:"3.2.93-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xen-linux-system-3.2.0-4-amd64", ver:"3.2.93-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xen-linux-system-3.2.0-5-686-pae", ver:"3.2.93-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xen-linux-system-3.2.0-5-amd64", ver:"3.2.93-1", rls:"DEB7")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}