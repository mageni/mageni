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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2021.0102");
  script_cve_id("CVE-2021-21781", "CVE-2021-26930", "CVE-2021-26931", "CVE-2021-26932");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-02-01T09:43:59+0000");
  script_tag(name:"last_modification", value:"2022-02-01 09:43:59 +0000 (Tue, 01 Feb 2022)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-03-31 00:15:00 +0000 (Wed, 31 Mar 2021)");

  script_name("Mageia: Security Advisory (MGASA-2021-0102)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2021-0102");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2021-0102.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=28471");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=28415");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.10.17");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.10.18");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.10.19");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel-linus' package(s) announced via the MGASA-2021-0102 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This kernel-linus update is based on upstream 5.10.19 and fixes at least
the following security issues:

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

For other upstream fixes, see the referenced changelogs.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-5.10.19-1.mga8", rpm:"kernel-linus-5.10.19-1.mga8~1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus", rpm:"kernel-linus~5.10.19~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-devel-5.10.19-1.mga8", rpm:"kernel-linus-devel-5.10.19-1.mga8~1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-devel-latest", rpm:"kernel-linus-devel-latest~5.10.19~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-doc", rpm:"kernel-linus-doc~5.10.19~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-latest", rpm:"kernel-linus-latest~5.10.19~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-source-5.10.19-1.mga8", rpm:"kernel-linus-source-5.10.19-1.mga8~1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-source-latest", rpm:"kernel-linus-source-latest~5.10.19~1.mga8", rls:"MAGEIA8"))) {
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
