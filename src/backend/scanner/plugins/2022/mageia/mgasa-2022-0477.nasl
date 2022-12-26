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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0477");
  script_cve_id("CVE-2022-3169", "CVE-2022-3344", "CVE-2022-3521", "CVE-2022-4139", "CVE-2022-42328", "CVE-2022-42329", "CVE-2022-4378", "CVE-2022-45869");
  script_tag(name:"creation_date", value:"2022-12-19 04:12:36 +0000 (Mon, 19 Dec 2022)");
  script_version("2022-12-19T04:12:36+0000");
  script_tag(name:"last_modification", value:"2022-12-19 04:12:36 +0000 (Mon, 19 Dec 2022)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-12-05 20:23:00 +0000 (Mon, 05 Dec 2022)");

  script_name("Mageia: Security Advisory (MGASA-2022-0477)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0477");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0477.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=31260");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.15.80");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.15.81");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.15.82");
  script_xref(name:"URL", value:"https://xenbits.xenproject.org/xsa/advisory-423.txt");
  script_xref(name:"URL", value:"https://xenbits.xenproject.org/xsa/advisory-424.txt");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel, kmod-virtualbox, kmod-xtables-addons' package(s) announced via the MGASA-2022-0477 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This kernel update is based on upstream 5.15.82 and fixes at least the
following security issues:

A flaw was found in the Linux kernel. A denial of service flaw may occur
if there is a consecutive request of the NVME_IOCTL_RESET and the
NVME_IOCTL_SUBSYS_RESET through the device file of the driver, resulting
in a PCIe link disconnect (CVE-2022-3169).

A flaw was found in the KVM's AMD nested virtualization (SVM). A malicious
L1 guest could purposely fail to intercept the shutdown of a cooperative
nested guest (L2), possibly leading to a page fault and kernel panic in
the host (L0) (CVE-2022-3344).

A vulnerability has been found in Linux Kernel function kcm_tx_work of the
file net/kcm/kcmsock.c of the component kcm. The manipulation leads to race
condition (CVE-2022-3521).

Guests can trigger NIC interface reset/abort/crash via netback. It is
possible for a guest to trigger a NIC interface reset/abort/crash in a
Linux based network backend by sending certain kinds of packets. It appears
to be an (unwritten?) assumption in the rest of the Linux network stack
that packet protocol headers are all contained within the linear section
of the SKB and some NICs behave badly if this is not the case. This has
been reported to occur with Cisco (enic) and Broadcom NetXtrem II BCM5780
(bnx2x) though it may be an issue with other NICs/drivers as well. In case
the frontend is sending requests with split headers, netback will forward
those violating above mentioned assumption to the networking core,
resulting in said misbehavior (CVE-2022-3643, XSA-423).

An incorrect TLB flush issue was found in the Linux kernel's GPU i915 kernel
driver, potentially leading to random memory corruption or data leaks. This
flaw could allow a local user to crash the system or escalate their
privileges on the system (CVE-2022-4139).

A stack overflow flaw was found in the Linux kernel's SYSCTL subsystem in
how a user changes certain kernel parameters and variables. This flaw
allows a local user to crash or potentially escalate their privileges on the
system (CVE-2022-4378).

The patch for XSA-392 introduced another issue which might result in
a deadlock when trying to free the SKB of a packet dropped due to
the XSA-392 handling (CVE-2022-42328, XSA-424).
Additionally when dropping packages for other reasons the same
deadlock could occur in case of netpoll being active for the interface
the xen-netback driver is connected to (CVE-2022-42329, XSA-424).

A race condition in the x86 KVM subsystem in the Linux kernel allows guest
OS users to cause a denial of service (host OS crash or host OS memory
corruption) when nested virtualisation and the TDP MMU are enabled
(CVE-2022-45869).

For other upstream fixes in this update, see the referenced changelogs.");

  script_tag(name:"affected", value:"'kernel, kmod-virtualbox, kmod-xtables-addons' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"bpftool", rpm:"bpftool~5.15.82~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cpupower", rpm:"cpupower~5.15.82~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cpupower-devel", rpm:"cpupower-devel~5.15.82~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~5.15.82~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop-5.15.82-1.mga8", rpm:"kernel-desktop-5.15.82-1.mga8~1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop-devel-5.15.82-1.mga8", rpm:"kernel-desktop-devel-5.15.82-1.mga8~1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop-devel-latest", rpm:"kernel-desktop-devel-latest~5.15.82~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop-latest", rpm:"kernel-desktop-latest~5.15.82~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop586-5.15.82-1.mga8", rpm:"kernel-desktop586-5.15.82-1.mga8~1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop586-devel-5.15.82-1.mga8", rpm:"kernel-desktop586-devel-5.15.82-1.mga8~1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop586-devel-latest", rpm:"kernel-desktop586-devel-latest~5.15.82~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop586-latest", rpm:"kernel-desktop586-latest~5.15.82~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~5.15.82~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-server-5.15.82-1.mga8", rpm:"kernel-server-5.15.82-1.mga8~1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-server-devel-5.15.82-1.mga8", rpm:"kernel-server-devel-5.15.82-1.mga8~1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-server-devel-latest", rpm:"kernel-server-devel-latest~5.15.82~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-server-latest", rpm:"kernel-server-latest~5.15.82~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-5.15.82-1.mga8", rpm:"kernel-source-5.15.82-1.mga8~1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-latest", rpm:"kernel-source-latest~5.15.82~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-userspace-headers", rpm:"kernel-userspace-headers~5.15.82~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmod-virtualbox", rpm:"kmod-virtualbox~7.0.4~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmod-xtables-addons", rpm:"kmod-xtables-addons~3.21~1.8.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64bpf-devel", rpm:"lib64bpf-devel~5.15.82~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64bpf0", rpm:"lib64bpf0~5.15.82~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbpf-devel", rpm:"libbpf-devel~5.15.82~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbpf0", rpm:"libbpf0~5.15.82~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~5.15.82~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-5.15.82-desktop-1.mga8", rpm:"virtualbox-kernel-5.15.82-desktop-1.mga8~7.0.4~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-5.15.82-server-1.mga8", rpm:"virtualbox-kernel-5.15.82-server-1.mga8~7.0.4~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-desktop-latest", rpm:"virtualbox-kernel-desktop-latest~7.0.4~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-server-latest", rpm:"virtualbox-kernel-server-latest~7.0.4~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-5.15.82-desktop-1.mga8", rpm:"xtables-addons-kernel-5.15.82-desktop-1.mga8~3.21~1.8.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-5.15.82-desktop586-1.mga8", rpm:"xtables-addons-kernel-5.15.82-desktop586-1.mga8~3.21~1.8.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-5.15.82-server-1.mga8", rpm:"xtables-addons-kernel-5.15.82-server-1.mga8~3.21~1.8.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-desktop-latest", rpm:"xtables-addons-kernel-desktop-latest~3.21~1.8.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-desktop586-latest", rpm:"xtables-addons-kernel-desktop586-latest~3.21~1.8.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-server-latest", rpm:"xtables-addons-kernel-server-latest~3.21~1.8.mga8", rls:"MAGEIA8"))) {
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
