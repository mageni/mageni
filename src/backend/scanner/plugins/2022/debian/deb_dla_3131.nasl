# Copyright (C) 2022 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.893131");
  script_version("2022-10-06T10:41:20+0000");
  script_cve_id("CVE-2021-33655", "CVE-2021-33656", "CVE-2021-4159", "CVE-2022-1462", "CVE-2022-1679", "CVE-2022-2153", "CVE-2022-2318", "CVE-2022-2586", "CVE-2022-2588", "CVE-2022-26365", "CVE-2022-26373", "CVE-2022-2663", "CVE-2022-3028", "CVE-2022-33740", "CVE-2022-33741", "CVE-2022-33742", "CVE-2022-33744", "CVE-2022-36879", "CVE-2022-36946", "CVE-2022-39188", "CVE-2022-39842", "CVE-2022-40307");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-10-06 10:41:20 +0000 (Thu, 06 Oct 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-05-24 22:22:00 +0000 (Tue, 24 May 2022)");
  script_tag(name:"creation_date", value:"2022-10-05 07:22:37 +0000 (Wed, 05 Oct 2022)");
  script_name("Debian LTS: Security Advisory for linux (DLA-3131-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2022/10/msg00000.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-3131-1");
  script_xref(name:"Advisory-ID", value:"DLA-3131-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/1018752");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux'
  package(s) announced via the DLA-3131-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Linux kernel that
may lead to privilege escalation, denial of service or information
leaks.

CVE-2021-4159

A flaw was found in the eBPF verifier which could lead to an
out-of-bounds read. If unprivileged use of eBPF is enabled, this
could leak sensitive information. This was already disabled by
default, which would fully mitigate the vulnerability.

CVE-2021-33655

A user with access to a framebuffer console device could cause a
memory out-of-bounds write via the FBIOPUT_VSCREENINFO ioctl.

CVE-2021-33656

A user with access to a framebuffer console device could cause a
memory out-of-bounds write via some font setting ioctls. These
obsolete ioctls have been removed.

CVE-2022-1462

'Little dog' reported a race condition in the pty (pseudo-terminal)
subsystem that can lead to a slab out-of-bounds write. A local
user could exploit this to cause a denial of service (crash or
memory corruption) or possibly for privilege escalation.

CVE-2022-1679

The syzbot tool found a race condition in the ath9k_htc driver
which can lead to a use-after-free. This might be exploitable to
cause a denial service (crash or memory corruption) or possibly
for privilege escalation.

CVE-2022-2153

'kangel' reported a flaw in the KVM implementation for x86
processors which could lead to a null pointer dereference. A local
user permitted to access /dev/kvm could exploit this to cause a
denial of service (crash).

CVE-2022-2318

A use-after-free in the Amateur Radio X.25 PLP (Rose) support may
result in denial of service.

CVE-2022-2586

A use-after-free in the Netfilter subsystem may result in local
privilege escalation for a user with the CAP_NET_ADMIN capability
in any user or network namespace.

CVE-2022-2588

Zhenpeng Lin discovered a use-after-free flaw in the cls_route
filter implementation which may result in local privilege
escalation for a user with the CAP_NET_ADMIN capability in any
user or network namespace.

CVE-2022-2663

David Leadbeater reported flaws in the nf_conntrack_irc
connection-tracking protocol module. When this module is enabled
on a firewall, an external user on the same IRC network as an
internal user could exploit its lax parsing to open arbitrary TCP
ports in the firewall, to reveal their public IP address, or to
block their IRC connection at the firewall.

CVE-2022-3028

Abhishek Shah reported a race condition in the AF_KEY subsystem,
which could lead to an out-of-bounds write or read. A local user
could exploit this to cause a denial of service (crash or memory
corruption), to obtain sensitive information, or possibly for
privilege escalation.

CVE-2022-26 ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'linux' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 10 buster, these problems have been fixed in version
4.19.260-1.

We recommend that you upgrade your linux packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"hyperv-daemons", ver:"4.19.260-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libbpf-dev", ver:"4.19.260-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libbpf4.19", ver:"4.19.260-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libcpupower-dev", ver:"4.19.260-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libcpupower1", ver:"4.19.260-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-compiler-gcc-8-arm", ver:"4.19.260-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-compiler-gcc-8-x86", ver:"4.19.260-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-config-4.19", ver:"4.19.260-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-cpupower", ver:"4.19.260-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-doc-4.19", ver:"4.19.260-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-19-686", ver:"4.19.260-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-19-686-pae", ver:"4.19.260-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-19-all", ver:"4.19.260-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-19-all-amd64", ver:"4.19.260-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-19-all-arm64", ver:"4.19.260-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-19-all-armhf", ver:"4.19.260-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-19-all-i386", ver:"4.19.260-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-19-amd64", ver:"4.19.260-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-19-arm64", ver:"4.19.260-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-19-armmp", ver:"4.19.260-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-19-armmp-lpae", ver:"4.19.260-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-19-cloud-amd64", ver:"4.19.260-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-19-common", ver:"4.19.260-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-19-common-rt", ver:"4.19.260-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-19-rt-686-pae", ver:"4.19.260-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-19-rt-amd64", ver:"4.19.260-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-19-rt-arm64", ver:"4.19.260-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-19-rt-armmp", ver:"4.19.260-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-22-686", ver:"4.19.260-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-22-686-pae", ver:"4.19.260-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-22-all", ver:"4.19.260-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-22-all-amd64", ver:"4.19.260-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-22-all-arm64", ver:"4.19.260-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-22-all-armhf", ver:"4.19.260-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-22-all-i386", ver:"4.19.260-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-22-amd64", ver:"4.19.260-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-22-arm64", ver:"4.19.260-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-22-armmp", ver:"4.19.260-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-22-armmp-lpae", ver:"4.19.260-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-22-cloud-amd64", ver:"4.19.260-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-22-common", ver:"4.19.260-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-22-common-rt", ver:"4.19.260-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-22-rt-686-pae", ver:"4.19.260-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-22-rt-amd64", ver:"4.19.260-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-22-rt-arm64", ver:"4.19.260-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-22-rt-armmp", ver:"4.19.260-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-19-686-dbg", ver:"4.19.260-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-19-686-pae-dbg", ver:"4.19.260-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-19-686-pae-unsigned", ver:"4.19.260-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-19-686-unsigned", ver:"4.19.260-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-19-amd64-dbg", ver:"4.19.260-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-19-amd64-unsigned", ver:"4.19.260-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-19-arm64-dbg", ver:"4.19.260-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-19-arm64-unsigned", ver:"4.19.260-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-19-armmp", ver:"4.19.260-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-19-armmp-dbg", ver:"4.19.260-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-19-armmp-lpae", ver:"4.19.260-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-19-armmp-lpae-dbg", ver:"4.19.260-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-19-cloud-amd64-dbg", ver:"4.19.260-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-19-cloud-amd64-unsigned", ver:"4.19.260-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-19-rt-686-pae-dbg", ver:"4.19.260-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-19-rt-686-pae-unsigned", ver:"4.19.260-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-19-rt-amd64-dbg", ver:"4.19.260-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-19-rt-amd64-unsigned", ver:"4.19.260-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-19-rt-arm64-dbg", ver:"4.19.260-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-19-rt-arm64-unsigned", ver:"4.19.260-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-19-rt-armmp", ver:"4.19.260-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-19-rt-armmp-dbg", ver:"4.19.260-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-22-686-dbg", ver:"4.19.260-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-22-686-pae-dbg", ver:"4.19.260-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-22-686-pae-unsigned", ver:"4.19.260-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-22-686-unsigned", ver:"4.19.260-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-22-amd64-dbg", ver:"4.19.260-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-22-amd64-unsigned", ver:"4.19.260-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-22-arm64-dbg", ver:"4.19.260-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-22-arm64-unsigned", ver:"4.19.260-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-22-armmp", ver:"4.19.260-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-22-armmp-dbg", ver:"4.19.260-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-22-armmp-lpae", ver:"4.19.260-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-22-armmp-lpae-dbg", ver:"4.19.260-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-22-cloud-amd64-dbg", ver:"4.19.260-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-22-cloud-amd64-unsigned", ver:"4.19.260-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-22-rt-686-pae-dbg", ver:"4.19.260-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-22-rt-686-pae-unsigned", ver:"4.19.260-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-22-rt-amd64-dbg", ver:"4.19.260-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-22-rt-amd64-unsigned", ver:"4.19.260-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-22-rt-arm64-dbg", ver:"4.19.260-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-22-rt-arm64-unsigned", ver:"4.19.260-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-22-rt-armmp", ver:"4.19.260-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-22-rt-armmp-dbg", ver:"4.19.260-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-amd64-signed-template", ver:"4.19.260-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-arm64-signed-template", ver:"4.19.260-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-i386-signed-template", ver:"4.19.260-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-kbuild-4.19", ver:"4.19.260-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-libc-dev", ver:"4.19.260-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-perf-4.19", ver:"4.19.260-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-source-4.19", ver:"4.19.260-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-support-4.19.0-19", ver:"4.19.260-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-support-4.19.0-22", ver:"4.19.260-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"usbip", ver:"4.19.260-1", rls:"DEB10"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
