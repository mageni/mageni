###############################################################################
# OpenVAS Vulnerability Test
# $Id: deb_4120.nasl 14281 2019-03-18 14:53:48Z cfischer $
#
# Auto-generated from advisory DSA 4120-1 using nvtgen 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.704120");
  script_version("$Revision: 14281 $");
  script_cve_id("CVE-2017-13166", "CVE-2017-5715", "CVE-2017-5753", "CVE-2017-5754", "CVE-2018-5750");
  script_name("Debian Security Advisory DSA 4120-1 (linux - security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:53:48 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2018-02-22 00:00:00 +0100 (Thu, 22 Feb 2018)");
  script_tag(name:"cvss_base", value:"4.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:N/A:N");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://www.debian.org/security/2018/dsa-4120.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");
  script_tag(name:"affected", value:"linux on Debian Linux");
  script_tag(name:"solution", value:"For the stable distribution (stretch), these problems have been fixed in
version 4.9.82-1+deb9u2.

We recommend that you upgrade your linux packages.

For the detailed security status of linux please refer to
its security tracker page linked in the references.");

  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/linux");
  script_tag(name:"summary", value:"Several vulnerabilities have been discovered in the Linux kernel that may
lead to a privilege escalation, denial of service or information leaks.

CVE-2017-5715
Multiple researchers have discovered a vulnerability in various
processors supporting speculative execution, enabling an attacker
controlling an unprivileged process to read memory from arbitrary
addresses, including from the kernel and all other processes running on
the system.

This specific attack has been named Spectre variant 2 (branch target
injection) and is mitigated in the Linux kernel for the Intel x86-64
architecture by using the retpoline
compiler feature which allows
indirect branches to be isolated from speculative execution.

CVE-2017-5754
Multiple researchers have discovered a vulnerability in Intel
processors, enabling an attacker controlling an unprivileged process to
read memory from arbitrary addresses, including from the kernel and all
other processes running on the system.

This specific attack has been named Meltdown and is addressed in the
Linux kernel on the powerpc/ppc64el architectures by flushing the L1
data cache on exit from kernel mode to user mode (or from hypervisor to
kernel).

This works on Power7, Power8 and Power9 processors.

CVE-2017-13166
A bug in the 32-bit compatibility layer of the v4l2 IOCTL handling code
has been found. Memory protections ensuring user-provided buffers always
point to userland memory were disabled, allowing destination address to
be in kernel space. This bug could be exploited by an attacker to
overwrite kernel memory from an unprivileged userland process, leading
to privilege escalation.

CVE-2018-5750
An information leak has been found in the Linux kernel. The
acpi_smbus_hc_add() prints a kernel address in the kernel log at every
boot, which could be used by an attacker on the system to defeat kernel
ASLR.

Additionnaly to those vulnerability, some mitigations for CVE-2017-5753
are
included in this release.

CVE-2017-5753
Multiple researchers have discovered a vulnerability in various
processors supporting speculative execution, enabling an attacker
controlling an unprivileged process to read memory from arbitrary
addresses, including from the kernel and all other processes running on
the system.

This specific attack has been named Spectre variant 1 (bounds-check
bypass) and is mitigated in the Linux kernel architecture by identifying
vulnerable code sections (array bounds checking followed by array
access) and replacing the array access with the speculation-safe
array_index_nospec() function.

More use sites will be added over time.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"hyperv-daemons", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libcpupower-dev", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libcpupower1", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libusbip-dev", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-compiler-gcc-6-arm", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-compiler-gcc-6-s390", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-compiler-gcc-6-x86", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-cpupower", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-doc-4.9", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-3-4kc-malta", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-3-5kc-malta", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-3-686", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-3-686-pae", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-3-all", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-3-all-amd64", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-3-all-arm64", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-3-all-armel", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-3-all-armhf", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-3-all-i386", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-3-all-mips", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-3-all-mips64el", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-3-all-mipsel", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-3-all-ppc64el", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-3-all-s390x", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-3-amd64", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-3-arm64", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-3-armmp", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-3-armmp-lpae", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-3-common", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-3-common-rt", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-3-loongson-3", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-3-marvell", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-3-octeon", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-3-powerpc64le", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-3-rt-686-pae", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-3-rt-amd64", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-3-s390x", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-4-4kc-malta", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-4-5kc-malta", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-4-686", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-4-686-pae", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-4-all", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-4-all-amd64", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-4-all-arm64", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-4-all-armel", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-4-all-armhf", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-4-all-i386", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-4-all-mips", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-4-all-mips64el", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-4-all-mipsel", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-4-all-ppc64el", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-4-all-s390x", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-4-amd64", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-4-arm64", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-4-armmp", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-4-armmp-lpae", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-4-common", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-4-common-rt", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-4-loongson-3", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-4-marvell", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-4-octeon", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-4-powerpc64le", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-4-rt-686-pae", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-4-rt-amd64", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-4-s390x", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-5-4kc-malta", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-5-5kc-malta", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-5-686", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-5-686-pae", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-5-all", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-5-all-amd64", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-5-all-arm64", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-5-all-armel", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-5-all-armhf", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-5-all-i386", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-5-all-mips", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-5-all-mips64el", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-5-all-mipsel", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-5-all-ppc64el", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-5-all-s390x", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-5-amd64", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-5-arm64", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-5-armmp", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-5-armmp-lpae", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-5-common", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-5-common-rt", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-5-loongson-3", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-5-marvell", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-5-octeon", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-5-powerpc64le", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-5-rt-686-pae", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-5-rt-amd64", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-5-s390x", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-6-4kc-malta", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-6-5kc-malta", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-6-686", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-6-686-pae", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-6-all", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-6-all-amd64", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-6-all-arm64", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-6-all-armel", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-6-all-armhf", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-6-all-i386", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-6-all-mips", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-6-all-mips64el", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-6-all-ppc64el", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-6-all-s390x", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-6-amd64", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-6-arm64", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-6-armmp", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-6-armmp-lpae", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-6-common", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-6-common-rt", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-6-loongson-3", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-6-marvell", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-6-octeon", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-6-powerpc64le", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-6-rt-686-pae", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-6-rt-amd64", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-6-s390x", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-3-4kc-malta", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-3-4kc-malta-dbg", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-3-5kc-malta", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-3-5kc-malta-dbg", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-3-686", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-3-686-dbg", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-3-686-pae", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-3-686-pae-dbg", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-3-amd64", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-3-amd64-dbg", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-3-arm64", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-3-arm64-dbg", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-3-armmp", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-3-armmp-dbg", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-3-armmp-lpae", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-3-armmp-lpae-dbg", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-3-loongson-3", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-3-loongson-3-dbg", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-3-marvell", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-3-marvell-dbg", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-3-octeon", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-3-octeon-dbg", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-3-powerpc64le", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-3-powerpc64le-dbg", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-3-rt-686-pae", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-3-rt-686-pae-dbg", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-3-rt-amd64", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-3-rt-amd64-dbg", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-3-s390x", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-3-s390x-dbg", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-4-4kc-malta", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-4-4kc-malta-dbg", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-4-5kc-malta", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-4-5kc-malta-dbg", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-4-686", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-4-686-dbg", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-4-686-pae", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-4-686-pae-dbg", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-4-amd64", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-4-amd64-dbg", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-4-arm64", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-4-arm64-dbg", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-4-armmp", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-4-armmp-dbg", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-4-armmp-lpae", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-4-armmp-lpae-dbg", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-4-loongson-3", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-4-loongson-3-dbg", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-4-marvell", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-4-marvell-dbg", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-4-octeon", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-4-octeon-dbg", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-4-powerpc64le", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-4-powerpc64le-dbg", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-4-rt-686-pae", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-4-rt-686-pae-dbg", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-4-rt-amd64", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-4-rt-amd64-dbg", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-4-s390x", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-4-s390x-dbg", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-5-4kc-malta", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-5-4kc-malta-dbg", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-5-5kc-malta", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-5-5kc-malta-dbg", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-5-686", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-5-686-dbg", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-5-686-pae", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-5-686-pae-dbg", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-5-amd64", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-5-amd64-dbg", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-5-arm64", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-5-arm64-dbg", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-5-armmp", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-5-armmp-dbg", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-5-armmp-lpae", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-5-armmp-lpae-dbg", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-5-loongson-3", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-5-loongson-3-dbg", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-5-marvell", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-5-marvell-dbg", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-5-octeon", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-5-octeon-dbg", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-5-powerpc64le", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-5-powerpc64le-dbg", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-5-rt-686-pae", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-5-rt-686-pae-dbg", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-5-rt-amd64", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-5-rt-amd64-dbg", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-5-s390x", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-5-s390x-dbg", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-6-4kc-malta", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-6-4kc-malta-dbg", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-6-5kc-malta", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-6-5kc-malta-dbg", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-6-686", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-6-686-dbg", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-6-686-pae", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-6-686-pae-dbg", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-6-amd64", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-6-amd64-dbg", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-6-arm64", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-6-arm64-dbg", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-6-armmp", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-6-armmp-dbg", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-6-armmp-lpae", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-6-armmp-lpae-dbg", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-6-loongson-3", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-6-loongson-3-dbg", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-6-marvell", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-6-marvell-dbg", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-6-octeon", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-6-octeon-dbg", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-6-powerpc64le", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-6-powerpc64le-dbg", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-6-rt-686-pae", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-6-rt-686-pae-dbg", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-6-rt-amd64", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-6-rt-amd64-dbg", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-6-s390x", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-6-s390x-dbg", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-kbuild-4.9", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-libc-dev", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-manual-4.9", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-perf-4.9", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-source-4.9", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-support-4.9.0-3", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-support-4.9.0-4", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-support-4.9.0-5", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-support-4.9.0-6", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"usbip", ver:"4.9.82-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}