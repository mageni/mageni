# Copyright (C) 2023 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2023.0088");
  script_cve_id("CVE-2022-2196", "CVE-2022-27672", "CVE-2022-3707", "CVE-2022-4129", "CVE-2022-4382", "CVE-2022-4842", "CVE-2023-0179", "CVE-2023-0394", "CVE-2023-1073", "CVE-2023-1074", "CVE-2023-1078", "CVE-2023-23559", "CVE-2023-26545");
  script_tag(name:"creation_date", value:"2023-03-28 00:26:44 +0000 (Tue, 28 Mar 2023)");
  script_version("2023-03-28T10:09:39+0000");
  script_tag(name:"last_modification", value:"2023-03-28 10:09:39 +0000 (Tue, 28 Mar 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-13 14:12:00 +0000 (Fri, 13 Jan 2023)");

  script_name("Mageia: Security Advisory (MGASA-2023-0088)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2023-0088");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2023-0088.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=31632");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.15.89");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.15.90");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.15.91");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.15.92");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.15.93");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.15.94");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.15.95");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.15.96");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.15.97");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.15.98");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel-linus' package(s) announced via the MGASA-2023-0088 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This kernel-linus update is based on upstream 5.15.98 and fixes at least the
following security issues:

A regression exists in the Linux Kernel within KVM: nVMX that allowed for
speculative execution attacks. L2 can carry out Spectre v2 attacks on L1
due to L1 thinking it doesn't need retpolines or IBPB after running L2
due to KVM (L0) advertising eIBRS support to L1. An attacker at L2 with
code execution can execute code on an indirect branch on the host machine
(CVE-2022-2196).

A double-free memory flaw was found in the Linux kernel. The Intel GVT-g
graphics driver triggers VGA card system resource overload, causing a
fail in the intel_gvt_dma_map_guest_page function. This issue could allow
a local user to crash the system (CVE-2022-3707).

A flaw was found in the Linux kernel's Layer 2 Tunneling Protocol (L2TP).
A missing lock when clearing sk_user_data can lead to a race condition
and NULL pointer dereference. A local user could use this flaw to
potentially crash the system causing a denial of service (CVE-2022-4129).

A use-after-free flaw caused by a race among the superblock operations in
the gadgetfs Linux driver was found. It could be triggered by yanking out
a device that is running the gadgetfs side (CVE-2022-4382).

A flaw NULL Pointer Dereference in the Linux kernel NTFS3 driver function
attr_punch_hole() was found. A local user could use this flaw to crash
the system (CVE-2022-4842).

When SMT is enabled, certain AMD processors may speculatively execute
instructions using a target from the sibling thread after an SMT mode
switch potentially resulting in information disclosure (CVE-2022-27672).

A buffer overflow vulnerability was found in the Netfilter subsystem in
the Linux Kernel. This issue could allow the leakage of both stack and
heap addresses, and potentially allow Local Privilege Escalation to the
root user via arbitrary code execution (CVE-2023-0179).

A NULL pointer dereference flaw was found in rawv6_push_pending_frames
in net/ipv6/raw.c in the network subcomponent in the Linux kernel. This
flaw causes the system to crash (CVE-2023-0394).

A memory corruption flaw was found in the Linux kernel's human interface
device (HID) subsystem in how a user inserts a malicious USB device. This
flaw allows a local user to crash or potentially escalate their privileges
on the system (CVE-2023-1073).

A memory leak flaw was found in the Linux kernel's Stream Control
Transmission Protocol. This issue may occur when a user starts a malicious
networking service and someone connects to this service. This could allow a
local user to starve resources, causing a denial of service (CVE-2023-1074).

rds: rds_rm_zerocopy_callback() use list_first_entry() (CVE-2023-1078).

An integer overflow flaw was found in the Linux kernel's wireless RNDIS
USB device driver in how a user installs a malicious USB device. This
flaw allows a local user to crash or potentially escalate ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel-linus' package(s) on Mageia 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "MAGEIA8") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-5.15.98-1.mga8", rpm:"kernel-linus-5.15.98-1.mga8~1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus", rpm:"kernel-linus~5.15.98~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-devel-5.15.98-1.mga8", rpm:"kernel-linus-devel-5.15.98-1.mga8~1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-devel-latest", rpm:"kernel-linus-devel-latest~5.15.98~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-doc", rpm:"kernel-linus-doc~5.15.98~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-latest", rpm:"kernel-linus-latest~5.15.98~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-source-5.15.98-1.mga8", rpm:"kernel-linus-source-5.15.98-1.mga8~1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-source-latest", rpm:"kernel-linus-source-latest~5.15.98~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
