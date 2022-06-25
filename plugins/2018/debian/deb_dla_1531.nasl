###############################################################################
# OpenVAS Vulnerability Test
# $Id: deb_dla_1531.nasl 14270 2019-03-18 14:24:29Z cfischer $
#
# Auto-generated from advisory DLA 1531-1 using nvtgen 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.891531");
  script_version("$Revision: 14270 $");
  script_cve_id("CVE-2018-10902", "CVE-2018-10938", "CVE-2018-13099", "CVE-2018-14609", "CVE-2018-14617",
                "CVE-2018-14633", "CVE-2018-14678", "CVE-2018-14734", "CVE-2018-15572", "CVE-2018-15594",
                "CVE-2018-16276", "CVE-2018-16658", "CVE-2018-17182", "CVE-2018-6554", "CVE-2018-6555",
                "CVE-2018-7755", "CVE-2018-9363", "CVE-2018-9516");
  script_name("Debian LTS Advisory ([SECURITY] [DLA 1531-1] linux-4.9 security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:24:29 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2018-10-04 00:00:00 +0200 (Thu, 04 Oct 2018)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:C");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2018/10/msg00003.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");
  script_tag(name:"affected", value:"linux-4.9 on Debian Linux");
  script_tag(name:"solution", value:"For Debian 8 'Jessie', these problems have been fixed in version
4.9.110-3+deb9u5~deb8u1.

We recommend that you upgrade your linux-4.9 packages.");
  script_tag(name:"summary", value:"Several vulnerabilities have been discovered in the Linux kernel that
may lead to a privilege escalation, denial of service or information
leaks.

CVE-2018-6554

A memory leak in the irda_bind function in the irda subsystem was
discovered. A local user can take advantage of this flaw to cause a
denial of service (memory consumption).

CVE-2018-6555

A flaw was discovered in the irda_setsockopt function in the irda
subsystem, allowing a local user to cause a denial of service
(use-after-free and system crash).

CVE-2018-7755

Brian Belleville discovered a flaw in the fd_locked_ioctl function
in the floppy driver in the Linux kernel. The floppy driver copies a
kernel pointer to user memory in response to the FDGETPRM ioctl. A
local user with access to a floppy drive device can take advantage
of this flaw to discover the location kernel code and data.

Description truncated. Please see the references for more information.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"linux-compiler-gcc-4.9-arm", ver:"4.9.110-3+deb9u5~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-doc-4.9", ver:"4.9.110-3+deb9u5~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.7-686", ver:"4.9.110-3+deb9u5~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.7-686-pae", ver:"4.9.110-3+deb9u5~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.7-all", ver:"4.9.110-3+deb9u5~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.7-all-amd64", ver:"4.9.110-3+deb9u5~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.7-all-armel", ver:"4.9.110-3+deb9u5~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.7-all-armhf", ver:"4.9.110-3+deb9u5~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.7-all-i386", ver:"4.9.110-3+deb9u5~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.7-amd64", ver:"4.9.110-3+deb9u5~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.7-armmp", ver:"4.9.110-3+deb9u5~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.7-armmp-lpae", ver:"4.9.110-3+deb9u5~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.7-common", ver:"4.9.110-3+deb9u5~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.7-common-rt", ver:"4.9.110-3+deb9u5~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.7-marvell", ver:"4.9.110-3+deb9u5~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.7-rt-686-pae", ver:"4.9.110-3+deb9u5~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.7-rt-amd64", ver:"4.9.110-3+deb9u5~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.8-686", ver:"4.9.110-3+deb9u5~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.8-686-pae", ver:"4.9.110-3+deb9u5~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.8-all", ver:"4.9.110-3+deb9u5~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.8-all-amd64", ver:"4.9.110-3+deb9u5~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.8-all-armel", ver:"4.9.110-3+deb9u5~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.8-all-armhf", ver:"4.9.110-3+deb9u5~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.8-all-i386", ver:"4.9.110-3+deb9u5~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.8-amd64", ver:"4.9.110-3+deb9u5~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.8-armmp", ver:"4.9.110-3+deb9u5~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.8-armmp-lpae", ver:"4.9.110-3+deb9u5~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.8-common", ver:"4.9.110-3+deb9u5~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.8-common-rt", ver:"4.9.110-3+deb9u5~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.8-marvell", ver:"4.9.110-3+deb9u5~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.8-rt-686-pae", ver:"4.9.110-3+deb9u5~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.8-rt-amd64", ver:"4.9.110-3+deb9u5~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.7-686", ver:"4.9.110-3+deb9u5~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.7-686-pae", ver:"4.9.110-3+deb9u5~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.7-686-pae-dbg", ver:"4.9.110-3+deb9u5~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.7-amd64", ver:"4.9.110-3+deb9u5~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.7-amd64-dbg", ver:"4.9.110-3+deb9u5~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.7-armmp", ver:"4.9.110-3+deb9u5~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.7-armmp-lpae", ver:"4.9.110-3+deb9u5~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.7-marvell", ver:"4.9.110-3+deb9u5~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.7-rt-686-pae", ver:"4.9.110-3+deb9u5~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.7-rt-686-pae-dbg", ver:"4.9.110-3+deb9u5~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.7-rt-amd64", ver:"4.9.110-3+deb9u5~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.7-rt-amd64-dbg", ver:"4.9.110-3+deb9u5~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.8-686", ver:"4.9.110-3+deb9u5~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.8-686-pae", ver:"4.9.110-3+deb9u5~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.8-686-pae-dbg", ver:"4.9.110-3+deb9u5~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.8-amd64", ver:"4.9.110-3+deb9u5~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.8-amd64-dbg", ver:"4.9.110-3+deb9u5~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.8-armmp", ver:"4.9.110-3+deb9u5~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.8-armmp-lpae", ver:"4.9.110-3+deb9u5~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.8-marvell", ver:"4.9.110-3+deb9u5~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.8-rt-686-pae", ver:"4.9.110-3+deb9u5~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.8-rt-686-pae-dbg", ver:"4.9.110-3+deb9u5~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.8-rt-amd64", ver:"4.9.110-3+deb9u5~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.8-rt-amd64-dbg", ver:"4.9.110-3+deb9u5~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-kbuild-4.9", ver:"4.9.110-3+deb9u5~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-manual-4.9", ver:"4.9.110-3+deb9u5~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-perf-4.9", ver:"4.9.110-3+deb9u5~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-source-4.9", ver:"4.9.110-3+deb9u5~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-support-4.9.0-0.bpo.7", ver:"4.9.110-3+deb9u5~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-support-4.9.0-0.bpo.8", ver:"4.9.110-3+deb9u5~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}