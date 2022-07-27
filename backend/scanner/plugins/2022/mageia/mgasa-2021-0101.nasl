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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2021.0101");
  script_cve_id("CVE-2021-21781", "CVE-2021-26930", "CVE-2021-26931", "CVE-2021-26932");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-02-01T09:43:59+0000");
  script_tag(name:"last_modification", value:"2022-02-01 09:43:59 +0000 (Tue, 01 Feb 2022)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-03-31 00:15:00 +0000 (Wed, 31 Mar 2021)");

  script_name("Mageia: Security Advisory (MGASA-2021-0101)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2021-0101");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2021-0101.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=28470");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=28435");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=28429");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=28417");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=28415");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=27910");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.10.17");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.10.18");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.10.19");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel, kmod-virtualbox, kmod-xtables-addons' package(s) announced via the MGASA-2021-0101 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This kernel update is based on upstream 5.10.19 and fixes at least the
following security issues:

An information disclosure vulnerability exists in the ARM SIGPAGE
functionality of Linux Kernel. A userland application can read the
contents of the sigpage, which can leak kernel memory contents. An
attacker can read a process's memory at a specific offset to trigger
this vulnerability (CVE-2021-21781).

An issue was discovered in the Linux kernel 3.11 through 5.10.16, as used
by Xen. To service requests to the PV backend, the driver maps grant
references provided by the frontend. In this process, errors may be
encountered. In one case, an error encountered earlier might be
discarded by later processing, resulting in the caller assuming
successful mapping, and hence subsequent operations trying to access
space that wasn't mapped. In another case, internal state would be
insufficiently updated, preventing safe recovery from the error
(CVE-2021-26930).

An issue was discovered in the Linux kernel 2.6.39 through 5.10.16, as
used in Xen. Block, net, and SCSI backends consider certain errors a
plain bug, deliberately causing a kernel crash. For errors potentially
being at least under the influence of guests (such as out of memory
conditions), it isn't correct to assume a plain bug. Memory allocations
potentially causing such crashes occur only when Linux is running in
PV mode, though (CVE-2021-26931).

An issue was discovered in the Linux kernel 3.2 through 5.10.16, as used
by Xen. Grant mapping operations often occur in batch hypercalls, where
a number of operations are done in a single hypercall, the success or
failure of each one is reported to the backend driver, and the backend
driver then loops over the results, performing follow-up actions based
on the success or failure of each operation. Unfortunately, when running
in PV mode, the Linux backend drivers mishandle this: Some errors are
ignored, effectively implying their success from the success of related
batch elements. In other cases, errors resulting from one batch element
lead to further batch elements not being inspected, and hence successful
ones to not be possible to properly unmap upon error recovery. Only
systems with Linux backends running in PV mode are vulnerable. Linux
backends run in HVM / PVH modes are not vulnerable (CVE-2021-26932).

It also adds the following fixes:
- enable ACPI_EC_DEBUGFS (mga#28415)
- drop 'revert 'Bluetooth: btusb: Add Qualcomm Bluetooth SoC WCN6855
 support' (mga#27910)'
- Bluetooth: btusb: fix for Qualcomm Bluetooth adapters that stopped working
 due to not finding (unneeded) ROME firmware (real fix for mga#27910)
- media: uvcvideo: Allow entities with no pads
- mm/vmscan: restore zone_reclaim_mode ABI
- nvme: Add quirks for Lexar 256GB SSD (pterjan, mga#28417)
- nvme: add 48-bit DMA address quirk for Amazon NVMe controllers
- nvme-pci: add the DISABLE_WRITE_ZEROES quirk for a ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"bpftool", rpm:"bpftool~5.10.19~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cpupower", rpm:"cpupower~5.10.19~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cpupower-devel", rpm:"cpupower-devel~5.10.19~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~5.10.19~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop-5.10.19-1.mga8", rpm:"kernel-desktop-5.10.19-1.mga8~1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop-devel-5.10.19-1.mga8", rpm:"kernel-desktop-devel-5.10.19-1.mga8~1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop-devel-latest", rpm:"kernel-desktop-devel-latest~5.10.19~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop-latest", rpm:"kernel-desktop-latest~5.10.19~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop586-5.10.19-1.mga8", rpm:"kernel-desktop586-5.10.19-1.mga8~1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop586-devel-5.10.19-1.mga8", rpm:"kernel-desktop586-devel-5.10.19-1.mga8~1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop586-devel-latest", rpm:"kernel-desktop586-devel-latest~5.10.19~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop586-latest", rpm:"kernel-desktop586-latest~5.10.19~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~5.10.19~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-server-5.10.19-1.mga8", rpm:"kernel-server-5.10.19-1.mga8~1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-server-devel-5.10.19-1.mga8", rpm:"kernel-server-devel-5.10.19-1.mga8~1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-server-devel-latest", rpm:"kernel-server-devel-latest~5.10.19~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-server-latest", rpm:"kernel-server-latest~5.10.19~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-5.10.19-1.mga8", rpm:"kernel-source-5.10.19-1.mga8~1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-latest", rpm:"kernel-source-latest~5.10.19~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-userspace-headers", rpm:"kernel-userspace-headers~5.10.19~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmod-virtualbox", rpm:"kmod-virtualbox~6.1.18~17.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmod-xtables-addons", rpm:"kmod-xtables-addons~3.13~33.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64bpf-devel", rpm:"lib64bpf-devel~5.10.19~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64bpf0", rpm:"lib64bpf0~5.10.19~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbpf-devel", rpm:"libbpf-devel~5.10.19~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbpf0", rpm:"libbpf0~5.10.19~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~5.10.19~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-5.10.19-desktop-1.mga8", rpm:"virtualbox-kernel-5.10.19-desktop-1.mga8~6.1.18~17.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-5.10.19-server-1.mga8", rpm:"virtualbox-kernel-5.10.19-server-1.mga8~6.1.18~17.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-desktop-latest", rpm:"virtualbox-kernel-desktop-latest~6.1.18~17.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-server-latest", rpm:"virtualbox-kernel-server-latest~6.1.18~17.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-5.10.19-desktop-1.mga8", rpm:"xtables-addons-kernel-5.10.19-desktop-1.mga8~3.13~33.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-5.10.19-desktop586-1.mga8", rpm:"xtables-addons-kernel-5.10.19-desktop586-1.mga8~3.13~33.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-5.10.19-server-1.mga8", rpm:"xtables-addons-kernel-5.10.19-server-1.mga8~3.13~33.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-desktop-latest", rpm:"xtables-addons-kernel-desktop-latest~3.13~33.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-desktop586-latest", rpm:"xtables-addons-kernel-desktop586-latest~3.13~33.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-server-latest", rpm:"xtables-addons-kernel-server-latest~3.13~33.mga8", rls:"MAGEIA8"))) {
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
