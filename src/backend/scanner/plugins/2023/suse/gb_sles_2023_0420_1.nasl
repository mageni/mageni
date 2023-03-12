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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.0420.1");
  script_cve_id("CVE-2018-9517", "CVE-2022-3564", "CVE-2022-3643", "CVE-2022-42895", "CVE-2022-42896", "CVE-2022-4662", "CVE-2022-47929", "CVE-2023-23454", "CVE-2023-23455");
  script_tag(name:"creation_date", value:"2023-02-16 04:21:52 +0000 (Thu, 16 Feb 2023)");
  script_version("2023-02-16T10:08:32+0000");
  script_tag(name:"last_modification", value:"2023-02-16 10:08:32 +0000 (Thu, 16 Feb 2023)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-12-12 15:27:00 +0000 (Mon, 12 Dec 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:0420-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:0420-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20230420-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2023:0420-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP2 kernel was updated to receive various security and bugfixes.


The following security bugs were fixed:

CVE-2018-9517: Fixed possible memory corruption due to a use after free
 in pppol2tp_connect (bsc#1108488).

CVE-2022-3564: Fixed use-after-free in l2cap_core.c of the Bluetooth
 component (bsc#1206073).

CVE-2022-3643: Fixed reset/abort/crash via netback from VM guest
 (bsc#1206113).

CVE-2022-42895: Fixed an information leak in the
 net/bluetooth/l2cap_core.c's l2cap_parse_conf_req() which can be used to
 leak kernel pointers remotely (bsc#1205705).

CVE-2022-42896: Fixed a use-after-free vulnerability in the
 net/bluetooth/l2cap_core.c's l2cap_connect() and l2cap_le_connect_req()
 which may have allowed code execution and leaking kernel memory
 (respectively) remotely via Bluetooth (bsc#1205709).

CVE-2022-4662: Fixed incorrect access control in the USB core subsystem
 that could lead a local user to crash the system (bsc#1206664).

CVE-2022-47929: Fixed NULL pointer dereference bug in the traffic
 control subsystem (bsc#1207237).

CVE-2023-23454: Fixed a type-confusion in the CBQ network scheduler
 (bsc#1207036).

CVE-2023-23455: Fixed a denial of service inside atm_tc_enqueue in
 net/sched/sch_atm.c because of type confusion (non-negative numbers can
 sometimes indicate a TC_ACT_SHOT condition rather than valid
 classification results) (bsc#1207125).

The following non-security bugs were fixed:

HID: betop: check shape of output reports (git-fixes, bsc#1207186).

HID: betop: fix slab-out-of-bounds Write in betop_probe (git-fixes).

HID: check empty report_list in hid_validate_values() (git-fixes,
 bsc#1206784).

sctp: fail if no bound addresses can be used for a given scope
 (bsc#1206677).");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 12-SP2.");

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

if(release == "SLES12.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.4.121~92.199.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.4.121~92.199.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base-debuginfo", rpm:"kernel-default-base-debuginfo~4.4.121~92.199.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debuginfo", rpm:"kernel-default-debuginfo~4.4.121~92.199.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debugsource", rpm:"kernel-default-debugsource~4.4.121~92.199.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.4.121~92.199.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.4.121~92.199.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.4.121~92.199.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.4.121~92.199.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.4.121~92.199.1", rls:"SLES12.0SP2"))) {
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
