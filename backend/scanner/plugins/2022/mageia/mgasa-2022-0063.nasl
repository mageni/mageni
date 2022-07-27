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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0063");
  script_cve_id("CVE-2022-0435", "CVE-2022-0492", "CVE-2022-24122", "CVE-2022-24448");
  script_tag(name:"creation_date", value:"2022-02-16 03:20:56 +0000 (Wed, 16 Feb 2022)");
  script_version("2022-02-16T15:36:35+0000");
  script_tag(name:"last_modification", value:"2022-02-17 11:13:34 +0000 (Thu, 17 Feb 2022)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-02-05 03:15:00 +0000 (Sat, 05 Feb 2022)");

  script_name("Mageia: Security Advisory (MGASA-2022-0063)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0063");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0063.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=30031");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=29965");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel-linus' package(s) announced via the MGASA-2022-0063 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This kernel-linus update is based on upstream 5.15.23 and fixes at least
the following security issues:

A stack overflow flaw was found in the Linux kernel TIPC protocol
functionality in the way a user sends a packet with malicious content
where the number of domain member nodes is higher than the 64 allowed.
This flaw allows a remote user to crash the system or possibly escalate
their privileges if they have access to the TIPC network (CVE-2022-0435).

A vulnerability was found in the Linux kernel cgroup_release_agent_write
in the kernel/cgroup/cgroup-v1.c function. This flaw, under certain
circumstances, allows the use of the cgroups v1 release_agent feature to
escalate privileges and bypass the namespace isolation unexpectedly
(CVE-2022-0492).

kernel/ucount.c in the Linux kernel 5.14 through 5.16.4, when unprivileged
user namespaces are enabled, allows a use-after-free and privilege
escalation because a ucounts object can outlive its namespace
(CVE-2022-24122).

An issue was discovered in fs/nfs/dir.c in the Linux kernel before 5.16.5.
If an application sets the O_DIRECTORY flag, and tries to open a regular
file, nfs_atomic_open() performs a regular lookup. If a regular file is
found, ENOTDIR should occur, but the server instead returns uninitialized
data in the file descriptor (CVE-2022-24448).

Other fixes in this update:
- enable several missed MediaTek wifi drivers (mga#29965)

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-5.15.23-1.mga8", rpm:"kernel-linus-5.15.23-1.mga8~1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus", rpm:"kernel-linus~5.15.23~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-devel-5.15.23-1.mga8", rpm:"kernel-linus-devel-5.15.23-1.mga8~1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-devel-latest", rpm:"kernel-linus-devel-latest~5.15.23~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-doc", rpm:"kernel-linus-doc~5.15.23~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-latest", rpm:"kernel-linus-latest~5.15.23~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-source-5.15.23-1.mga8", rpm:"kernel-linus-source-5.15.23-1.mga8~1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-source-latest", rpm:"kernel-linus-source-latest~5.15.23~1.mga8", rls:"MAGEIA8"))) {
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
