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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.0209.1");
  script_cve_id("CVE-2022-3491", "CVE-2022-3520", "CVE-2022-3591", "CVE-2022-3705", "CVE-2022-4141", "CVE-2022-4292", "CVE-2022-4293", "CVE-2023-0049", "CVE-2023-0051", "CVE-2023-0054", "CVE-2023-0288", "CVE-2023-0433");
  script_tag(name:"creation_date", value:"2023-01-31 04:22:00 +0000 (Tue, 31 Jan 2023)");
  script_version("2023-01-31T10:08:41+0000");
  script_tag(name:"last_modification", value:"2023-01-31 10:08:41 +0000 (Tue, 31 Jan 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-12-06 12:26:00 +0000 (Tue, 06 Dec 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:0209-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2|SLES12\.0SP4|SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:0209-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20230209-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'vim' package(s) announced via the SUSE-SU-2023:0209-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for vim fixes the following issues:

Updated to version 9.0.1234:
 - CVE-2023-0433: Fixed an out of bounds memory access that could cause a
 crash (bsc#1207396).
 - CVE-2023-0288: Fixed an out of bounds memory access that could cause a
 crash (bsc#1207162).
 - CVE-2023-0054: Fixed an out of bounds memory write that could cause a
 crash or memory corruption (bsc#1206868).
 - CVE-2023-0051: Fixed an out of bounds memory access that could cause a
 crash (bsc#1206867).
 - CVE-2023-0049: Fixed an out of bounds memory access that could cause a
 crash (bsc#1206866).
 - CVE-2022-3491: Fixed an out of bounds memory access that could cause a
 crash (bsc#1206028).
 - CVE-2022-3520: Fixed an out of bounds memory access that could cause a
 crash (bsc#1206071).
 - CVE-2022-3591: Fixed a use-after-free issue that could cause memory
 corruption or undefined behavior (bsc#1206072).
 - CVE-2022-4292: Fixed a use-after-free issue that could cause memory
 corruption or undefined behavior (bsc#1206075).
 - CVE-2022-4293: Fixed a floating point exception that could cause a
 crash (bsc#1206077).
 - CVE-2022-4141: Fixed an out of bounds memory write that could cause a
 crash or memory corruption (bsc#1205797).
 - CVE-2022-3705: Fixed an use-after-free issue that could cause a crash
 or memory corruption (bsc#1204779).");

  script_tag(name:"affected", value:"'vim' package(s) on SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP 12-SP4, SUSE OpenStack Cloud 9, SUSE OpenStack Cloud Crowbar 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"gvim", rpm:"gvim~9.0.1234~17.12.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gvim-debuginfo", rpm:"gvim-debuginfo~9.0.1234~17.12.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim", rpm:"vim~9.0.1234~17.12.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-data", rpm:"vim-data~9.0.1234~17.12.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-data-common", rpm:"vim-data-common~9.0.1234~17.12.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-debuginfo", rpm:"vim-debuginfo~9.0.1234~17.12.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-debugsource", rpm:"vim-debugsource~9.0.1234~17.12.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"gvim", rpm:"gvim~9.0.1234~17.12.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gvim-debuginfo", rpm:"gvim-debuginfo~9.0.1234~17.12.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim", rpm:"vim~9.0.1234~17.12.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-data", rpm:"vim-data~9.0.1234~17.12.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-data-common", rpm:"vim-data-common~9.0.1234~17.12.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-debuginfo", rpm:"vim-debuginfo~9.0.1234~17.12.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-debugsource", rpm:"vim-debugsource~9.0.1234~17.12.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"gvim", rpm:"gvim~9.0.1234~17.12.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gvim-debuginfo", rpm:"gvim-debuginfo~9.0.1234~17.12.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim", rpm:"vim~9.0.1234~17.12.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-data", rpm:"vim-data~9.0.1234~17.12.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-data-common", rpm:"vim-data-common~9.0.1234~17.12.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-debuginfo", rpm:"vim-debuginfo~9.0.1234~17.12.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-debugsource", rpm:"vim-debugsource~9.0.1234~17.12.1", rls:"SLES12.0SP5"))) {
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
