# Copyright (C) 2020 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892323");
  script_version("2020-08-17T13:22:16+0000");
  script_cve_id("CVE-2017-5715", "CVE-2018-3639", "CVE-2019-18814", "CVE-2019-18885", "CVE-2019-20810", "CVE-2020-10766", "CVE-2020-10767", "CVE-2020-10768", "CVE-2020-12655", "CVE-2020-12771", "CVE-2020-13974", "CVE-2020-15393");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-08-18 10:12:19 +0000 (Tue, 18 Aug 2020)");
  script_tag(name:"creation_date", value:"2020-08-17 13:22:16 +0000 (Mon, 17 Aug 2020)");
  script_name("Debian LTS: Security Advisory for linux-4.19 (DLA-2323-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2020/08/msg00019.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2323-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/958300");
  script_xref(name:"URL", value:"https://bugs.debian.org/960493");
  script_xref(name:"URL", value:"https://bugs.debian.org/962254");
  script_xref(name:"URL", value:"https://bugs.debian.org/963493");
  script_xref(name:"URL", value:"https://bugs.debian.org/964153");
  script_xref(name:"URL", value:"https://bugs.debian.org/964480");
  script_xref(name:"URL", value:"https://bugs.debian.org/965365");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-4.19'
  package(s) announced via the DLA-2323-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Linux 4.19 has been packaged for Debian 9 as linux-4.19. This
provides a supported upgrade path for systems that currently use
kernel packages from the 'stretch-backports' suite.

There is no need to upgrade systems using Linux 4.9, as that kernel
version will also continue to be supported in the LTS period.

This backport does not include the following binary packages:

hyperv-daemons libbpf-dev libbpf4.19 libcpupower-dev libcpupower1
liblockdep-dev liblockdep4.19 linux-compiler-gcc-6-arm
linux-compiler-gcc-6-x86 linux-cpupower linux-libc-dev lockdep
usbip

Older versions of most of those are built from the linux source
package in Debian 9.

The kernel images and modules will not be signed for use on systems
with Secure Boot enabled, as there is no support for this in Debian 9.

Several vulnerabilities have been discovered in the Linux kernel that
may lead to a denial of service or information leak.

CVE-2019-18814

Navid Emamdoost reported a potential use-after-free in the
AppArmor security module, in the case that audit rule
initialisation fails. The security impact of this is unclear.

CVE-2019-18885

The 'bobfuzzer' team discovered that crafted Btrfs volumes could
trigger a crash (oops). An attacker able to mount such a volume
could use this to cause a denial of service.

CVE-2019-20810

A potential memory leak was discovered in the go7007 media driver.
The security impact of this is unclear.

CVE-2020-10766

Anthony Steinhauser reported a flaw in the mitigation for
Speculative Store Bypass (CVE-2018-3639) on x86 CPUs. A local
user could use this to temporarily disable SSB mitigation in other
users' tasks. If those other tasks run sandboxed code, this would
allow that code to read sensitive information in the same process
but outside the sandbox.

CVE-2020-10767

Anthony Steinhauser reported a flaw in the mitigation for Spectre
variant 2 (CVE-2017-5715) on x86 CPUs. Depending on which other
mitigations the CPU supports, the kernel might not use IBPB to
mitigate Spectre variant 2 in user-space. A local user could use
this to read sensitive information from other users' processes.

CVE-2020-10768

Anthony Steinhauser reported a flaw in the mitigation for Spectre
variant 2 (CVE-2017-5715) on x86 CPUs. After a task force-
disabled indirect branch speculation through prctl(), it could
still re-enable it later, so it was not possible to override a
program that explicitly enabled it.

CVE-2020-12655

Zheng Bin reported that crafted XFS volumes could trigger a system
hang. An attacker able to mount such a volume could use this to
cause a denial of service.

CVE-2020-12771

Zhiqiang Liu reported a bug in the bcache b ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'linux-4.19' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 9 'Stretch', these problems have been fixed in version
4.19.132-1~deb9u1. This update additionally fixes Debian bugs
#958300, #960493, #962254, #963493, #964153, #964480, and #965365, and
includes many more bug fixes from stable updates 4.19.119-4.19.132
inclusive.

We recommend that you upgrade your linux-4.19 packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"linux-config-4.19", ver:"4.19.132-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-doc-4.19", ver:"4.19.132-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-0.bpo.10-686", ver:"4.19.132-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-0.bpo.10-686-pae", ver:"4.19.132-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-0.bpo.10-all", ver:"4.19.132-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-0.bpo.10-all-amd64", ver:"4.19.132-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-0.bpo.10-all-arm64", ver:"4.19.132-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-0.bpo.10-all-armel", ver:"4.19.132-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-0.bpo.10-all-armhf", ver:"4.19.132-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-0.bpo.10-all-i386", ver:"4.19.132-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-0.bpo.10-amd64", ver:"4.19.132-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-0.bpo.10-arm64", ver:"4.19.132-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-0.bpo.10-armmp", ver:"4.19.132-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-0.bpo.10-armmp-lpae", ver:"4.19.132-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-0.bpo.10-cloud-amd64", ver:"4.19.132-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-0.bpo.10-common", ver:"4.19.132-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-0.bpo.10-common-rt", ver:"4.19.132-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-0.bpo.10-marvell", ver:"4.19.132-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-0.bpo.10-rpi", ver:"4.19.132-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-0.bpo.10-rt-686-pae", ver:"4.19.132-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-0.bpo.10-rt-amd64", ver:"4.19.132-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-0.bpo.10-rt-arm64", ver:"4.19.132-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-0.bpo.10-rt-armmp", ver:"4.19.132-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.10-686", ver:"4.19.132-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.10-686-dbg", ver:"4.19.132-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.10-686-pae", ver:"4.19.132-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.10-686-pae-dbg", ver:"4.19.132-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.10-amd64", ver:"4.19.132-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.10-amd64-dbg", ver:"4.19.132-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.10-arm64", ver:"4.19.132-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.10-arm64-dbg", ver:"4.19.132-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.10-armmp", ver:"4.19.132-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.10-armmp-dbg", ver:"4.19.132-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.10-armmp-lpae", ver:"4.19.132-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.10-armmp-lpae-dbg", ver:"4.19.132-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.10-cloud-amd64", ver:"4.19.132-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.10-cloud-amd64-dbg", ver:"4.19.132-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.10-marvell", ver:"4.19.132-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.10-marvell-dbg", ver:"4.19.132-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.10-rpi", ver:"4.19.132-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.10-rpi-dbg", ver:"4.19.132-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.10-rt-686-pae", ver:"4.19.132-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.10-rt-686-pae-dbg", ver:"4.19.132-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.10-rt-amd64", ver:"4.19.132-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.10-rt-amd64-dbg", ver:"4.19.132-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.10-rt-arm64", ver:"4.19.132-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.10-rt-arm64-dbg", ver:"4.19.132-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.10-rt-armmp", ver:"4.19.132-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.10-rt-armmp-dbg", ver:"4.19.132-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-kbuild-4.19", ver:"4.19.132-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-perf-4.19", ver:"4.19.132-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-source-4.19", ver:"4.19.132-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-support-4.19.0-0.bpo.10", ver:"4.19.132-1~deb9u1", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
