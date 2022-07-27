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
  script_oid("1.3.6.1.4.1.25623.1.0.704667");
  script_version("2020-04-30T03:00:30+0000");
  script_cve_id("CVE-2020-10942", "CVE-2020-11565", "CVE-2020-11884", "CVE-2020-2732", "CVE-2020-8428");
  script_tag(name:"cvss_base", value:"5.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:N/I:P/A:C");
  script_tag(name:"last_modification", value:"2020-04-30 03:00:30 +0000 (Thu, 30 Apr 2020)");
  script_tag(name:"creation_date", value:"2020-04-30 03:00:30 +0000 (Thu, 30 Apr 2020)");
  script_name("Debian: Security Advisory for linux (DSA-4667-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"URL", value:"https://www.debian.org/security/2020/dsa-4667.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4667-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux'
  package(s) announced via the DSA-4667-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Linux kernel that
may lead to a privilege escalation, denial of service, or information
leak.

CVE-2020-2732 
Paulo Bonzini discovered that the KVM implementation for Intel
processors did not properly handle instruction emulation for L2
guests when nested virtualization is enabled. This could allow
an L2 guest to cause privilege escalation, denial of service,
or information leaks in the L1 guest.

CVE-2020-8428 
Al Viro discovered a use-after-free vulnerability in the VFS
layer. This allowed local users to cause a denial-of-service
(crash) or obtain sensitive information from kernel memory.

CVE-2020-10942 
It was discovered that the vhost_net driver did not properly
validate the type of sockets set as back-ends. A local user
permitted to access /dev/vhost-net could use this to cause a stack
corruption via crafted system calls, resulting in denial of
service (crash) or possibly privilege escalation.

CVE-2020-11565
Entropy Moe reported that the shared memory filesystem (tmpfs) did
not correctly handle an mpol 
mount option specifying an empty
node list, leading to a stack-based out-of-bounds write. If user
namespaces are enabled, a local user could use this to cause a
denial of service (crash) or possibly for privilege escalation.

CVE-2020-11884 
Al Viro reported a race condition in memory management code for
IBM Z (s390x architecture), that can result in the kernel
executing code from the user address space. A local user could
use this for privilege escalation.");

  script_tag(name:"affected", value:"'linux' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For the stable distribution (buster), these problems have been fixed in
version 4.19.98-1+deb10u1.

We recommend that you upgrade your linux packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"hyperv-daemons", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libbpf-dev", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libbpf4.19", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libcpupower-dev", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libcpupower1", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"liblockdep-dev", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"liblockdep4.19", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-compiler-gcc-8-arm", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-compiler-gcc-8-s390", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-compiler-gcc-8-x86", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-config-4.19", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-cpupower", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-doc-4.19", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-6-4kc-malta", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-6-5kc-malta", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-6-686", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-6-686-pae", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-6-all", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-6-all-amd64", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-6-all-arm64", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-6-all-armel", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-6-all-armhf", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-6-all-i386", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-6-all-mips", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-6-all-mips64el", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-6-all-mipsel", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-6-all-ppc64el", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-6-all-s390x", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-6-amd64", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-6-arm64", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-6-armmp", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-6-armmp-lpae", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-6-cloud-amd64", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-6-common", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-6-common-rt", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-6-loongson-3", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-6-marvell", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-6-octeon", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-6-powerpc64le", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-6-rpi", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-6-rt-686-pae", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-6-rt-amd64", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-6-rt-arm64", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-6-rt-armmp", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-6-s390x", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-8-4kc-malta", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-8-5kc-malta", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-8-686", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-8-686-pae", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-8-all", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-8-all-amd64", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-8-all-arm64", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-8-all-armel", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-8-all-armhf", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-8-all-i386", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-8-all-mips", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-8-all-mips64el", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-8-all-mipsel", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-8-all-ppc64el", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-8-all-s390x", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-8-amd64", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-8-arm64", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-8-armmp", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-8-armmp-lpae", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-8-cloud-amd64", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-8-common", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-8-common-rt", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-8-loongson-3", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-8-marvell", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-8-octeon", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-8-powerpc64le", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-8-rpi", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-8-rt-686-pae", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-8-rt-amd64", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-8-rt-arm64", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-8-rt-armmp", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-8-s390x", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-6-4kc-malta", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-6-4kc-malta-dbg", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-6-5kc-malta", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-6-5kc-malta-dbg", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-6-686-dbg", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-6-686-pae-dbg", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-6-686-pae-unsigned", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-6-686-unsigned", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-6-amd64-dbg", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-6-amd64-unsigned", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-6-arm64-dbg", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-6-arm64-unsigned", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-6-armmp", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-6-armmp-dbg", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-6-armmp-lpae", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-6-armmp-lpae-dbg", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-6-cloud-amd64-dbg", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-6-cloud-amd64-unsigned", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-6-loongson-3", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-6-loongson-3-dbg", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-6-marvell", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-6-marvell-dbg", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-6-octeon", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-6-octeon-dbg", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-6-powerpc64le", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-6-powerpc64le-dbg", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-6-rpi", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-6-rpi-dbg", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-6-rt-686-pae-dbg", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-6-rt-686-pae-unsigned", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-6-rt-amd64-dbg", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-6-rt-amd64-unsigned", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-6-rt-arm64-dbg", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-6-rt-arm64-unsigned", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-6-rt-armmp", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-6-rt-armmp-dbg", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-6-s390x", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-6-s390x-dbg", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-8-4kc-malta", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-8-4kc-malta-dbg", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-8-5kc-malta", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-8-5kc-malta-dbg", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-8-686-dbg", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-8-686-pae-dbg", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-8-686-pae-unsigned", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-8-686-unsigned", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-8-amd64-dbg", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-8-amd64-unsigned", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-8-arm64-dbg", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-8-arm64-unsigned", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-8-armmp", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-8-armmp-dbg", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-8-armmp-lpae", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-8-armmp-lpae-dbg", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-8-cloud-amd64-dbg", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-8-cloud-amd64-unsigned", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-8-loongson-3", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-8-loongson-3-dbg", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-8-marvell", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-8-marvell-dbg", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-8-octeon", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-8-octeon-dbg", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-8-powerpc64le", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-8-powerpc64le-dbg", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-8-rpi", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-8-rpi-dbg", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-8-rt-686-pae-dbg", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-8-rt-686-pae-unsigned", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-8-rt-amd64-dbg", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-8-rt-amd64-unsigned", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-8-rt-arm64-dbg", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-8-rt-arm64-unsigned", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-8-rt-armmp", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-8-rt-armmp-dbg", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-8-s390x", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-8-s390x-dbg", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-amd64-signed-template", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-arm64-signed-template", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-i386-signed-template", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-kbuild-4.19", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-libc-dev", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-perf-4.19", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-source-4.19", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-support-4.19.0-6", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-support-4.19.0-8", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"lockdep", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"usbip", ver:"4.19.98-1+deb10u1", rls:"DEB10"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
