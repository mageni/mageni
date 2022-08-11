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
  script_oid("1.3.6.1.4.1.25623.1.0.854751");
  script_version("2022-06-17T06:43:01+0000");
  script_cve_id("CVE-2017-17087", "CVE-2021-3778", "CVE-2021-3796", "CVE-2021-3872", "CVE-2021-3875", "CVE-2021-3903", "CVE-2021-3927", "CVE-2021-3928", "CVE-2021-3968", "CVE-2021-3973", "CVE-2021-3974", "CVE-2021-3984", "CVE-2021-4019", "CVE-2021-4069", "CVE-2021-4136", "CVE-2021-4166", "CVE-2021-4192", "CVE-2021-4193", "CVE-2021-46059", "CVE-2022-0128", "CVE-2022-0213", "CVE-2022-0261", "CVE-2022-0318", "CVE-2022-0319", "CVE-2022-0351", "CVE-2022-0359", "CVE-2022-0361", "CVE-2022-0392", "CVE-2022-0407", "CVE-2022-0413", "CVE-2022-0696", "CVE-2022-1381", "CVE-2022-1420", "CVE-2022-1616", "CVE-2022-1619", "CVE-2022-1620", "CVE-2022-1733", "CVE-2022-1735", "CVE-2022-1771", "CVE-2022-1785", "CVE-2022-1796", "CVE-2022-1851", "CVE-2022-1897", "CVE-2022-1898", "CVE-2022-1927");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-06-17 09:50:23 +0000 (Fri, 17 Jun 2022)");
  script_tag(name:"creation_date", value:"2022-06-17 01:03:13 +0000 (Fri, 17 Jun 2022)");
  script_name("openSUSE: Security Advisory for vim (SUSE-SU-2022:2102-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.4|openSUSELeap15\.3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:2102-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/A7IIKQP3UXOLJI2SID6AOU2NSGRK776Z");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'vim'
  package(s) announced via the SUSE-SU-2022:2102-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for vim fixes the following issues:

  - CVE-2017-17087: Fixed information leak via .swp files (bsc#1070955).

  - CVE-2021-3875: Fixed heap-based buffer overflow (bsc#1191770).

  - CVE-2021-3903: Fixed heap-based buffer overflow (bsc#1192167).

  - CVE-2021-3968: Fixed heap-based buffer overflow (bsc#1192902).

  - CVE-2021-3973: Fixed heap-based buffer overflow (bsc#1192903).

  - CVE-2021-3974: Fixed use-after-free (bsc#1192904).

  - CVE-2021-4069: Fixed use-after-free in ex_open()in src/ex_docmd.c
       (bsc#1193466).

  - CVE-2021-4136: Fixed heap-based buffer overflow (bsc#1193905).

  - CVE-2021-4166: Fixed out-of-bounds read (bsc#1194093).

  - CVE-2021-4192: Fixed use-after-free (bsc#1194217).

  - CVE-2021-4193: Fixed out-of-bounds read (bsc#1194216).

  - CVE-2022-0128: Fixed out-of-bounds read (bsc#1194388).

  - CVE-2022-0213: Fixed heap-based buffer overflow (bsc#1194885).

  - CVE-2022-0261: Fixed heap-based buffer overflow (bsc#1194872).

  - CVE-2022-0318: Fixed heap-based buffer overflow (bsc#1195004).

  - CVE-2022-0359: Fixed heap-based buffer overflow in init_ccline() in
       ex_getln.c (bsc#1195203).

  - CVE-2022-0392: Fixed heap-based buffer overflow (bsc#1195332).

  - CVE-2022-0407: Fixed heap-based buffer overflow (bsc#1195354).

  - CVE-2022-0696: Fixed NULL pointer dereference (bsc#1196361).

  - CVE-2022-1381: Fixed global heap buffer overflow in skip_range
       (bsc#1198596).

  - CVE-2022-1420: Fixed out-of-range pointer offset (bsc#1198748).

  - CVE-2022-1616: Fixed use-after-free in append_command (bsc#1199331).

  - CVE-2022-1619: Fixed heap-based Buffer Overflow in function
       cmdline_erase_chars (bsc#1199333).

  - CVE-2022-1620: Fixed NULL pointer dereference in function
       vim_regexec_string (bsc#1199334).

  - CVE-2022-1733: Fixed heap-based buffer overflow in cindent.c
       (bsc#1199655).

  - CVE-2022-1735: Fixed heap-based buffer overflow (bsc#1199651).

  - CVE-2022-1771: Fixed stack exhaustion (bsc#1199693).

  - CVE-2022-1785: Fixed out-of-bounds write (bsc#1199745).

  - CVE-2022-1796: Fixed use-after-free in find_pattern_in_path
       (bsc#1199747).

  - CVE-2022-1851: Fixed out-of-bounds read (bsc#1199936).

  - CVE-2022-1897: Fixed out-of-bounds write (bsc#1200010).

  - CVE-2022-1898: Fixed use-after-free (bsc#1200011).

  - CVE-2022-1927: Fixed buffer over-read (bsc#1200012).");

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

  if(!isnull(res = isrpmvuln(pkg:"gvim", rpm:"gvim~8.2.5038~150000.5.21.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gvim-debuginfo", rpm:"gvim-debuginfo~8.2.5038~150000.5.21.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim", rpm:"vim~8.2.5038~150000.5.21.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-debuginfo", rpm:"vim-debuginfo~8.2.5038~150000.5.21.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-debugsource", rpm:"vim-debugsource~8.2.5038~150000.5.21.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-small", rpm:"vim-small~8.2.5038~150000.5.21.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-small-debuginfo", rpm:"vim-small-debuginfo~8.2.5038~150000.5.21.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-data", rpm:"vim-data~8.2.5038~150000.5.21.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-data-common", rpm:"vim-data-common~8.2.5038~150000.5.21.1", rls:"openSUSELeap15.4"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"gvim", rpm:"gvim~8.2.5038~150000.5.21.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gvim-debuginfo", rpm:"gvim-debuginfo~8.2.5038~150000.5.21.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim", rpm:"vim~8.2.5038~150000.5.21.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-debuginfo", rpm:"vim-debuginfo~8.2.5038~150000.5.21.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-debugsource", rpm:"vim-debugsource~8.2.5038~150000.5.21.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-small", rpm:"vim-small~8.2.5038~150000.5.21.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-small-debuginfo", rpm:"vim-small-debuginfo~8.2.5038~150000.5.21.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-data", rpm:"vim-data~8.2.5038~150000.5.21.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-data-common", rpm:"vim-data-common~8.2.5038~150000.5.21.1", rls:"openSUSELeap15.3"))) {
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