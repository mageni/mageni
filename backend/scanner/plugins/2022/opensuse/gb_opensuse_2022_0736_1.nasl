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
  script_oid("1.3.6.1.4.1.25623.1.0.854529");
  script_version("2022-03-15T08:14:31+0000");
  script_cve_id("CVE-2021-3778", "CVE-2021-3796", "CVE-2021-3872", "CVE-2021-3927", "CVE-2021-3928", "CVE-2021-3984", "CVE-2021-4019", "CVE-2021-4193", "CVE-2021-46059", "CVE-2022-0318", "CVE-2022-0319", "CVE-2022-0351", "CVE-2022-0361", "CVE-2022-0413");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-03-15 11:02:07 +0000 (Tue, 15 Mar 2022)");
  script_tag(name:"creation_date", value:"2022-03-05 02:01:24 +0000 (Sat, 05 Mar 2022)");
  script_name("openSUSE: Security Advisory for vim (openSUSE-SU-2022:0736-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.4|openSUSELeap15\.3)");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2022:0736-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/FDNZ3N5S7UGKPUUKPGOQQGPJJK3YTW37");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'vim'
  package(s) announced via the openSUSE-SU-2022:0736-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for vim fixes the following issues:

  - CVE-2022-0318: Fixed heap-based buffer overflow (bsc#1195004).

  - CVE-2021-3796: Fixed use-after-free in nv_replace() in normal.c
       (bsc#1190570).

  - CVE-2021-3872: Fixed heap-based buffer overflow in win_redr_status()
       drawscreen.c (bsc#1191893).

  - CVE-2021-3927: Fixed heap-based buffer overflow (bsc#1192481).

  - CVE-2021-3928: Fixed stack-based buffer overflow (bsc#1192478).

  - CVE-2021-4019: Fixed heap-based buffer overflow (bsc#1193294).

  - CVE-2021-3984: Fixed illegal memory access when C-indenting could have
       led to heap buffer overflow (bsc#1193298).

  - CVE-2021-3778: Fixed heap-based buffer overflow in regexp_nfa.c
       (bsc#1190533).

  - CVE-2021-4193: Fixed out-of-bounds read (bsc#1194216).

  - CVE-2021-46059: Fixed pointer dereference vulnerability via the
       vim_regexec_multi function at regexp.c (bsc#1194556).

  - CVE-2022-0319: Fixded out-of-bounds read (bsc#1195066).

  - CVE-2022-0351: Fixed uncontrolled recursion in eval7() (bsc#1195126).

  - CVE-2022-0361: Fixed buffer overflow (bsc#1195126).

  - CVE-2022-0413: Fixed use-after-free in src/ex_cmds.c (bsc#1195356).");

  script_tag(name:"affected", value:"'vim' package(s) on openSUSE Leap 15.3, openSUSE Leap 15.4.");

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

if(release == "openSUSELeap15.4") {

  if(!isnull(res = isrpmvuln(pkg:"gvim", rpm:"gvim~8.0.1568~5.17.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gvim-debuginfo", rpm:"gvim-debuginfo~8.0.1568~5.17.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim", rpm:"vim~8.0.1568~5.17.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-debuginfo", rpm:"vim-debuginfo~8.0.1568~5.17.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-debugsource", rpm:"vim-debugsource~8.0.1568~5.17.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-small", rpm:"vim-small~8.0.1568~5.17.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-small-debuginfo", rpm:"vim-small-debuginfo~8.0.1568~5.17.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-data", rpm:"vim-data~8.0.1568~5.17.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-data-common", rpm:"vim-data-common~8.0.1568~5.17.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeap15.3") {

  if(!isnull(res = isrpmvuln(pkg:"gvim", rpm:"gvim~8.0.1568~5.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gvim-debuginfo", rpm:"gvim-debuginfo~8.0.1568~5.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim", rpm:"vim~8.0.1568~5.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-debuginfo", rpm:"vim-debuginfo~8.0.1568~5.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-debugsource", rpm:"vim-debugsource~8.0.1568~5.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-small", rpm:"vim-small~8.0.1568~5.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-small-debuginfo", rpm:"vim-small-debuginfo~8.0.1568~5.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-data", rpm:"vim-data~8.0.1568~5.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-data-common", rpm:"vim-data-common~8.0.1568~5.17.1", rls:"openSUSELeap15.3"))) {
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