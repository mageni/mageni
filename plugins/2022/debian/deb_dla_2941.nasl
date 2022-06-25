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
  script_oid("1.3.6.1.4.1.25623.1.0.892941");
  script_version("2022-03-10T02:00:49+0000");
  script_cve_id("CVE-2020-29374", "CVE-2020-36322", "CVE-2021-20317", "CVE-2021-20321", "CVE-2021-20322", "CVE-2021-22600", "CVE-2021-28711", "CVE-2021-28712", "CVE-2021-28713", "CVE-2021-28714", "CVE-2021-28715", "CVE-2021-28950", "CVE-2021-3640", "CVE-2021-3744", "CVE-2021-3752", "CVE-2021-3760", "CVE-2021-3764", "CVE-2021-3772", "CVE-2021-38300", "CVE-2021-39685", "CVE-2021-39686", "CVE-2021-39698", "CVE-2021-39713", "CVE-2021-4002", "CVE-2021-4083", "CVE-2021-4135", "CVE-2021-4155", "CVE-2021-41864", "CVE-2021-4202", "CVE-2021-4203", "CVE-2021-42739", "CVE-2021-43389", "CVE-2021-43975", "CVE-2021-43976", "CVE-2021-44733", "CVE-2021-45095", "CVE-2021-45469", "CVE-2021-45480", "CVE-2022-0001", "CVE-2022-0002", "CVE-2022-0322", "CVE-2022-0330", "CVE-2022-0435", "CVE-2022-0487", "CVE-2022-0492", "CVE-2022-0617", "CVE-2022-0644", "CVE-2022-22942", "CVE-2022-24448", "CVE-2022-24959", "CVE-2022-25258", "CVE-2022-25375");
  script_tag(name:"cvss_base", value:"7.9");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-03-10 11:17:35 +0000 (Thu, 10 Mar 2022)");
  script_tag(name:"creation_date", value:"2022-03-10 02:00:49 +0000 (Thu, 10 Mar 2022)");
  script_name("Debian LTS: Security Advisory for linux-4.19 (DLA-2941-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2022/03/msg00012.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2941-1");
  script_xref(name:"Advisory-ID", value:"DLA-2941-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/988044");
  script_xref(name:"URL", value:"https://bugs.debian.org/989285");
  script_xref(name:"URL", value:"https://bugs.debian.org/990411");
  script_xref(name:"URL", value:"https://bugs.debian.org/994050");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-4.19'
  package(s) announced via the DLA-2941-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Linux kernel that
may lead to a privilege escalation, denial of service or information
leaks.

CVE-2020-29374

Jann Horn of Google reported a flaw in Linux's virtual memory
management. A parent and child process initially share all their
memory, but when either writes to a shared page, the page is
duplicated and unshared (copy-on-write). However, in case an
operation such as vmsplice() required the kernel to take an
additional reference to a shared page, and a copy-on-write occurs
during this operation, the kernel might have accessed the wrong
process's memory. For some programs, this could lead to an
information leak or data corruption.

This issue was already fixed for most architectures, but not on
MIPS and System z. This update corrects that.

CVE-2020-36322, CVE-2021-28950

The syzbot tool found that the FUSE (filesystem-in-user-space)
implementation did not correctly handle a FUSE server returning
invalid attributes for a file. A local user permitted to run a
FUSE server could use this to cause a denial of service (crash).

The original fix for this introduced a different potential denial
of service (infinite loop in kernel space), which has also been
fixed.

CVE-2021-3640

Lin Ma discovered a race condition in the Bluetooth protocol
implementation that can lead to a use-after-free. A local
user could exploit this to cause a denial of service (memory
corruption or crash) or possibly for privilege escalation.

CVE-2021-3744, CVE-2021-3764

minihanshen reported bugs in the ccp driver for AMD
Cryptographic Coprocessors that could lead to a resource leak.
On systems using this driver, a local user could exploit this to
cause a denial of service.

CVE-2021-3752

Likang Luo of NSFOCUS Security Team discovered a flaw in the
Bluetooth L2CAP implementation that can lead to a user-after-free.
A local user could exploit this to cause a denial of service
(memory corruption or crash) or possibly for privilege escalation.

CVE-2021-3760, CVE-2021-4202

Lin Ma discovered race conditions in the NCI (NFC Controller
Interface) driver, which could lead to a use-after-free. A local
user could exploit this to cause a denial of service (memory
corruption or crash) or possibly for privilege escalation.

This driver is not enabled in Debian's official kernel
configurations.

CVE-2021-3772

A flaw was found in the SCTP protocol implementation, which would
allow a networked attacker to break an SCTP association. The
attacker would only need to know or guess the IP addresses and
ports for the association.

CVE-2021-4002

It was discovered that hugetlbfs, the virtual filesystem used  ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'linux-4.19' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 9 stretch, these problems have been fixed in version
4.19.232-1~deb9u1. This update additionally includes many more bug
fixes from stable updates 4.19.209-4.19.232 inclusive.

We recommend that you upgrade your linux-4.19 packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"linux-config-4.19", ver:"4.19.232-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-doc-4.19", ver:"4.19.232-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-0.bpo.18-686", ver:"4.19.232-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-0.bpo.18-686-pae", ver:"4.19.232-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-0.bpo.18-all", ver:"4.19.232-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-0.bpo.18-all-amd64", ver:"4.19.232-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-0.bpo.18-all-arm64", ver:"4.19.232-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-0.bpo.18-all-armel", ver:"4.19.232-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-0.bpo.18-all-armhf", ver:"4.19.232-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-0.bpo.18-all-i386", ver:"4.19.232-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-0.bpo.18-amd64", ver:"4.19.232-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-0.bpo.18-arm64", ver:"4.19.232-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-0.bpo.18-armmp", ver:"4.19.232-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-0.bpo.18-armmp-lpae", ver:"4.19.232-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-0.bpo.18-cloud-amd64", ver:"4.19.232-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-0.bpo.18-common", ver:"4.19.232-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-0.bpo.18-common-rt", ver:"4.19.232-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-0.bpo.18-marvell", ver:"4.19.232-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-0.bpo.18-rpi", ver:"4.19.232-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-0.bpo.18-rt-686-pae", ver:"4.19.232-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-0.bpo.18-rt-amd64", ver:"4.19.232-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-0.bpo.18-rt-arm64", ver:"4.19.232-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-0.bpo.18-rt-armmp", ver:"4.19.232-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-0.bpo.19-686", ver:"4.19.232-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-0.bpo.19-686-pae", ver:"4.19.232-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-0.bpo.19-all", ver:"4.19.232-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-0.bpo.19-all-amd64", ver:"4.19.232-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-0.bpo.19-all-arm64", ver:"4.19.232-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-0.bpo.19-all-armel", ver:"4.19.232-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-0.bpo.19-all-armhf", ver:"4.19.232-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-0.bpo.19-all-i386", ver:"4.19.232-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-0.bpo.19-amd64", ver:"4.19.232-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-0.bpo.19-arm64", ver:"4.19.232-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-0.bpo.19-armmp", ver:"4.19.232-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-0.bpo.19-armmp-lpae", ver:"4.19.232-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-0.bpo.19-cloud-amd64", ver:"4.19.232-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-0.bpo.19-common", ver:"4.19.232-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-0.bpo.19-common-rt", ver:"4.19.232-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-0.bpo.19-marvell", ver:"4.19.232-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-0.bpo.19-rpi", ver:"4.19.232-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-0.bpo.19-rt-686-pae", ver:"4.19.232-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-0.bpo.19-rt-amd64", ver:"4.19.232-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-0.bpo.19-rt-arm64", ver:"4.19.232-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-0.bpo.19-rt-armmp", ver:"4.19.232-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.18-686", ver:"4.19.232-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.18-686-dbg", ver:"4.19.232-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.18-686-pae", ver:"4.19.232-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.18-686-pae-dbg", ver:"4.19.232-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.18-amd64", ver:"4.19.232-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.18-amd64-dbg", ver:"4.19.232-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.18-arm64", ver:"4.19.232-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.18-arm64-dbg", ver:"4.19.232-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.18-armmp", ver:"4.19.232-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.18-armmp-dbg", ver:"4.19.232-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.18-armmp-lpae", ver:"4.19.232-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.18-armmp-lpae-dbg", ver:"4.19.232-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.18-cloud-amd64", ver:"4.19.232-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.18-cloud-amd64-dbg", ver:"4.19.232-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.18-marvell", ver:"4.19.232-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.18-marvell-dbg", ver:"4.19.232-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.18-rpi", ver:"4.19.232-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.18-rpi-dbg", ver:"4.19.232-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.18-rt-686-pae", ver:"4.19.232-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.18-rt-686-pae-dbg", ver:"4.19.232-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.18-rt-amd64", ver:"4.19.232-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.18-rt-amd64-dbg", ver:"4.19.232-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.18-rt-arm64", ver:"4.19.232-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.18-rt-arm64-dbg", ver:"4.19.232-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.18-rt-armmp", ver:"4.19.232-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.18-rt-armmp-dbg", ver:"4.19.232-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.19-686", ver:"4.19.232-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.19-686-dbg", ver:"4.19.232-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.19-686-pae", ver:"4.19.232-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.19-686-pae-dbg", ver:"4.19.232-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.19-amd64", ver:"4.19.232-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.19-amd64-dbg", ver:"4.19.232-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.19-arm64", ver:"4.19.232-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.19-arm64-dbg", ver:"4.19.232-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.19-armmp", ver:"4.19.232-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.19-armmp-dbg", ver:"4.19.232-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.19-armmp-lpae", ver:"4.19.232-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.19-armmp-lpae-dbg", ver:"4.19.232-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.19-cloud-amd64", ver:"4.19.232-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.19-cloud-amd64-dbg", ver:"4.19.232-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.19-marvell", ver:"4.19.232-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.19-marvell-dbg", ver:"4.19.232-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.19-rpi", ver:"4.19.232-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.19-rpi-dbg", ver:"4.19.232-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.19-rt-686-pae", ver:"4.19.232-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.19-rt-686-pae-dbg", ver:"4.19.232-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.19-rt-amd64", ver:"4.19.232-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.19-rt-amd64-dbg", ver:"4.19.232-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.19-rt-arm64", ver:"4.19.232-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.19-rt-arm64-dbg", ver:"4.19.232-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.19-rt-armmp", ver:"4.19.232-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.19-rt-armmp-dbg", ver:"4.19.232-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-kbuild-4.19", ver:"4.19.232-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-perf-4.19", ver:"4.19.232-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-source-4.19", ver:"4.19.232-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-support-4.19.0-0.bpo.18", ver:"4.19.232-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-support-4.19.0-0.bpo.19", ver:"4.19.232-1~deb9u1", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
