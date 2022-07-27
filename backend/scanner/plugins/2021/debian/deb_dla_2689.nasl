# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.892689");
  script_version("2021-06-24T05:32:21+0000");
  script_cve_id("CVE-2020-24586", "CVE-2020-24587", "CVE-2020-24588", "CVE-2020-25670", "CVE-2020-25671", "CVE-2020-25672", "CVE-2020-26139", "CVE-2020-26147", "CVE-2020-26558", "CVE-2020-29374", "CVE-2020-36322", "CVE-2021-0129", "CVE-2021-20292", "CVE-2021-23133", "CVE-2021-23134", "CVE-2021-26930", "CVE-2021-28660", "CVE-2021-28688", "CVE-2021-28950", "CVE-2021-28964", "CVE-2021-28971", "CVE-2021-29154", "CVE-2021-29265", "CVE-2021-29647", "CVE-2021-29650", "CVE-2021-30002", "CVE-2021-31916", "CVE-2021-32399", "CVE-2021-33034", "CVE-2021-3428", "CVE-2021-3483", "CVE-2021-3564", "CVE-2021-3573", "CVE-2021-3587");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2021-06-25 10:20:56 +0000 (Fri, 25 Jun 2021)");
  script_tag(name:"creation_date", value:"2021-06-24 05:32:21 +0000 (Thu, 24 Jun 2021)");
  script_name("Debian LTS: Security Advisory for linux (DLA-2689-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2021/06/msg00020.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2689-1");
  script_xref(name:"Advisory-ID", value:"DLA-2689-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux'
  package(s) announced via the DLA-2689-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Linux kernel that
may lead to the execution of arbitrary code, privilege escalation,
denial of service, or information leaks.

This update is not yet available for the armel (ARM EABI soft-float)
architecture.

CVE-2020-24586, CVE-2020-24587, CVE-2020-26147

Mathy Vanhoef discovered that many Wi-Fi implementations,
including Linux's mac80211, did not correctly implement reassembly
of fragmented packets. In some circumstances, an attacker within
range of a network could exploit these flaws to forge arbitrary
packets and/or to access sensitive data on that network.

CVE-2020-24588

Mathy Vanhoef discovered that most Wi-Fi implementations,
including Linux's mac80211, did not authenticate the 'is
aggregated' packet header flag. An attacker within range of a
network could exploit this to forge arbitrary packets on that
network.

CVE-2020-25670, CVE-2020-25671, CVE-2021-23134

kiyin of TenCent discovered several reference counting bugs
in the NFC LLCP implementation which could lead to use-after-free.
A local user could exploit these for denial of service (crash or
memory corruption) or possibly for privilege escalation.

Nadav Markus and Or Cohen of Palo Alto Networks discovered that
the original fixes for these introduced a new bug that could
result in use-after-free and double-free. This has also been
fixed.

CVE-2020-25672

kiyin of TenCent discovered a memory leak in the NFC LLCP
implementation. A local user could exploit this for denial of
service (memory exhaustion).

CVE-2020-26139

Mathy Vanhoef discovered that a bug in some Wi-Fi implementations,
including Linux's mac80211. When operating in AP mode, they would
forward EAPOL frames from one client to another while the sender
was not yet authenticated. An attacker within range of a network
could use this for denial of service or as an aid to exploiting
other vulnerabilities.

CVE-2020-26558, CVE-2021-0129

Researchers at ANSSI discovered vulnerabilities in the Bluetooth
Passkey authentication method, and in Linux's implementation of
it. An attacker within range of two Bluetooth devices while they
pair using Passkey authentication could exploit this to obtain the
shared secret (Passkey) and then impersonate either of the devices
to each other.

CVE-2020-29374

Jann Horn of Google reported a flaw in Linux's virtual memory
management. A parent and child process initially share all their
memory, but when either writes to a shared page, the page is
duplicated and unshared (copy-on-write). However, in case an
operation such as vmsplice() required the kernel to take an
additional reference to a shared page, and a  ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'linux' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 9 stretch, these problems have been fixed in version
4.9.272-1. This update additionally includes many more bug fixes from
stable updates 4.9.259-4.9.272 inclusive.

We recommend that you upgrade your linux packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"hyperv-daemons", ver:"4.9.272-1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libcpupower-dev", ver:"4.9.272-1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libcpupower1", ver:"4.9.272-1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libusbip-dev", ver:"4.9.272-1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-compiler-gcc-6-arm", ver:"4.9.272-1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-compiler-gcc-6-x86", ver:"4.9.272-1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-cpupower", ver:"4.9.272-1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-doc-4.9", ver:"4.9.272-1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-14-686", ver:"4.9.272-1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-14-686-pae", ver:"4.9.272-1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-14-all", ver:"4.9.272-1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-14-all-amd64", ver:"4.9.272-1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-14-all-arm64", ver:"4.9.272-1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-14-all-armel", ver:"4.9.272-1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-14-all-armhf", ver:"4.9.272-1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-14-all-i386", ver:"4.9.272-1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-14-amd64", ver:"4.9.272-1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-14-arm64", ver:"4.9.272-1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-14-armmp", ver:"4.9.272-1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-14-armmp-lpae", ver:"4.9.272-1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-14-common", ver:"4.9.272-1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-14-common-rt", ver:"4.9.272-1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-14-marvell", ver:"4.9.272-1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-14-rt-686-pae", ver:"4.9.272-1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-14-rt-amd64", ver:"4.9.272-1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-15-686", ver:"4.9.272-1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-15-686-pae", ver:"4.9.272-1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-15-all", ver:"4.9.272-1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-15-all-amd64", ver:"4.9.272-1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-15-all-arm64", ver:"4.9.272-1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-15-all-armel", ver:"4.9.272-1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-15-all-armhf", ver:"4.9.272-1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-15-all-i386", ver:"4.9.272-1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-15-amd64", ver:"4.9.272-1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-15-arm64", ver:"4.9.272-1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-15-armmp", ver:"4.9.272-1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-15-armmp-lpae", ver:"4.9.272-1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-15-common", ver:"4.9.272-1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-15-common-rt", ver:"4.9.272-1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-15-marvell", ver:"4.9.272-1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-15-rt-686-pae", ver:"4.9.272-1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-15-rt-amd64", ver:"4.9.272-1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-16-686", ver:"4.9.272-1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-16-686-pae", ver:"4.9.272-1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-16-all", ver:"4.9.272-1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-16-all-amd64", ver:"4.9.272-1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-16-all-arm64", ver:"4.9.272-1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-16-all-armhf", ver:"4.9.272-1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-16-all-i386", ver:"4.9.272-1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-16-amd64", ver:"4.9.272-1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-16-arm64", ver:"4.9.272-1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-16-armmp", ver:"4.9.272-1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-16-armmp-lpae", ver:"4.9.272-1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-16-common", ver:"4.9.272-1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-16-common-rt", ver:"4.9.272-1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-16-rt-686-pae", ver:"4.9.272-1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-16-rt-amd64", ver:"4.9.272-1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-14-686", ver:"4.9.272-1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-14-686-dbg", ver:"4.9.272-1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-14-686-pae", ver:"4.9.272-1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-14-686-pae-dbg", ver:"4.9.272-1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-14-amd64", ver:"4.9.272-1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-14-amd64-dbg", ver:"4.9.272-1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-14-arm64", ver:"4.9.272-1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-14-arm64-dbg", ver:"4.9.272-1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-14-armmp", ver:"4.9.272-1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-14-armmp-dbg", ver:"4.9.272-1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-14-armmp-lpae", ver:"4.9.272-1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-14-armmp-lpae-dbg", ver:"4.9.272-1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-14-marvell", ver:"4.9.272-1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-14-marvell-dbg", ver:"4.9.272-1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-14-rt-686-pae", ver:"4.9.272-1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-14-rt-686-pae-dbg", ver:"4.9.272-1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-14-rt-amd64", ver:"4.9.272-1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-14-rt-amd64-dbg", ver:"4.9.272-1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-15-686", ver:"4.9.272-1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-15-686-dbg", ver:"4.9.272-1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-15-686-pae", ver:"4.9.272-1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-15-686-pae-dbg", ver:"4.9.272-1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-15-amd64", ver:"4.9.272-1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-15-amd64-dbg", ver:"4.9.272-1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-15-arm64", ver:"4.9.272-1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-15-arm64-dbg", ver:"4.9.272-1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-15-armmp", ver:"4.9.272-1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-15-armmp-dbg", ver:"4.9.272-1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-15-armmp-lpae", ver:"4.9.272-1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-15-armmp-lpae-dbg", ver:"4.9.272-1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-15-marvell", ver:"4.9.272-1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-15-marvell-dbg", ver:"4.9.272-1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-15-rt-686-pae", ver:"4.9.272-1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-15-rt-686-pae-dbg", ver:"4.9.272-1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-15-rt-amd64", ver:"4.9.272-1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-15-rt-amd64-dbg", ver:"4.9.272-1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-16-686", ver:"4.9.272-1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-16-686-dbg", ver:"4.9.272-1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-16-686-pae", ver:"4.9.272-1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-16-686-pae-dbg", ver:"4.9.272-1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-16-amd64", ver:"4.9.272-1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-16-amd64-dbg", ver:"4.9.272-1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-16-arm64", ver:"4.9.272-1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-16-arm64-dbg", ver:"4.9.272-1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-16-armmp", ver:"4.9.272-1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-16-armmp-dbg", ver:"4.9.272-1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-16-armmp-lpae", ver:"4.9.272-1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-16-armmp-lpae-dbg", ver:"4.9.272-1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-16-rt-686-pae", ver:"4.9.272-1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-16-rt-686-pae-dbg", ver:"4.9.272-1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-16-rt-amd64", ver:"4.9.272-1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-16-rt-amd64-dbg", ver:"4.9.272-1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-kbuild-4.9", ver:"4.9.272-1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-libc-dev", ver:"4.9.272-1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-manual-4.9", ver:"4.9.272-1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-perf-4.9", ver:"4.9.272-1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-source-4.9", ver:"4.9.272-1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-support-4.9.0-14", ver:"4.9.272-1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-support-4.9.0-15", ver:"4.9.272-1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-support-4.9.0-16", ver:"4.9.272-1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"usbip", ver:"4.9.272-1", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
