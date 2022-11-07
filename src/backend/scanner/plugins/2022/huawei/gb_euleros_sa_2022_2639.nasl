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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2022.2639");
  script_cve_id("CVE-2022-1616", "CVE-2022-1620", "CVE-2022-1621", "CVE-2022-1629", "CVE-2022-1733", "CVE-2022-1735", "CVE-2022-1796", "CVE-2022-1851", "CVE-2022-1897", "CVE-2022-1898", "CVE-2022-1942", "CVE-2022-1968", "CVE-2022-2000", "CVE-2022-2042", "CVE-2022-2124", "CVE-2022-2125", "CVE-2022-2126", "CVE-2022-2183", "CVE-2022-2206", "CVE-2022-2207", "CVE-2022-2208", "CVE-2022-2210", "CVE-2022-2284", "CVE-2022-2285", "CVE-2022-2287", "CVE-2022-2289", "CVE-2022-2304", "CVE-2022-2345");
  script_tag(name:"creation_date", value:"2022-10-28 04:30:21 +0000 (Fri, 28 Oct 2022)");
  script_version("2022-10-28T04:30:21+0000");
  script_tag(name:"last_modification", value:"2022-10-28 04:30:21 +0000 (Fri, 28 Oct 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-06 18:20:00 +0000 (Wed, 06 Jul 2022)");

  script_name("Huawei EulerOS: Security Advisory for vim (EulerOS-SA-2022-2639)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP3");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2022-2639");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2022-2639");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'vim' package(s) announced via the EulerOS-SA-2022-2639 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Out-of-bounds read in function gchar_cursor at misc1.c:532(CVE-2022-1851)

Heap-based Buffer Overflow in function vim_regsub_both at regexp.c:1954(CVE-2022-1942)

Use After Free in function utf_ptr2char at mbyte.c:1794(CVE-2022-1968)

Out-of-bounds write in function append_command at ex_docmd.c:3447(CVE-2022-2000)

When fuzzing vim commit 1d97db3d9 (works with latest build and latest commit 3760bfddc per this time of this report), I discovered a use after free.(CVE-2022-2042)

When fuzzing vim commit fc78a0369 (works with latest build and latest commit 202b4bd3a per this time of this report) with clang 13 and ASan, I discovered a buffer overflow.(CVE-2022-1616)

NULL Pointer Dereference in function vim_regexec_string at regexp.c:2729 allows attackers to cause a denial of service (application crash) via a crafted input.(CVE-2022-1620)

When fuzzing vim commit fc78a0369 (works with latest build and latest commit 202b4bd3a per this time of this report) with clang 13 and ASan, I discovered a buffer overflow.(CVE-2022-1621)

Buffer Over-read in function find_next_quote at textobject.c:1663(CVE-2022-1629)

Heap-based Buffer Overflow in function skip_string at cindent.c:92(CVE-2022-1733)

Buffer Over-read in function utfc_ptr2len at mbyte.c:2113(CVE-2022-1735)

heap-use-after-free in function find_pattern_in_path at search.c:3683(CVE-2022-1796)

Out-of-bounds write in function vim_regsub_both at regexp.c:1954(CVE-2022-1897)

Use After Free in function find_pattern_in_path at search.c:3653(CVE-2022-1898)

Use After Free in GitHub repository vim/vim prior to 9.0.0046.(CVE-2022-2345)

Buffer Over-read in GitHub repository vim/vim prior to 8.2.(CVE-2022-2124)

Heap-based Buffer Overflow in GitHub repository vim/vim prior to 8.2.(CVE-2022-2125)

Out-of-bounds Read in GitHub repository vim/vim prior to 8.2.(CVE-2022-2126)

Out-of-bounds Read in GitHub repository vim/vim prior to 8.2.(CVE-2022-2183)

Out-of-bounds Read in GitHub repository vim/vim prior to 8.2.(CVE-2022-2206)

Heap-based Buffer Overflow in GitHub repository vim/vim prior to 8.2.(CVE-2022-2207)

NULL Pointer Dereference in GitHub repository vim/vim prior to 8.2.5163.(CVE-2022-2208)

Out-of-bounds Write in GitHub repository vim/vim prior to 8.2.(CVE-2022-2210)

Heap-based Buffer Overflow in GitHub repository vim/vim prior to 9.0.(CVE-2022-2284)

Integer Overflow or Wraparound in GitHub repository vim/vim prior to 9.0.(CVE-2022-2285)

Out-of-bounds Read in GitHub repository vim/vim prior to 9.0.(CVE-2022-2287)

Stack-based Buffer Overflow in GitHub repository vim/vim prior to 9.0.(CVE-2022-2304)

Use After Free in GitHub repository vim/vim prior to 9.0.(CVE-2022-2289)");

  script_tag(name:"affected", value:"'vim' package(s) on Huawei EulerOS V2.0SP3.");

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

if(release == "EULEROS-2.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"vim-X11", rpm:"vim-X11~7.4.160~2.h30", rls:"EULEROS-2.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-common", rpm:"vim-common~7.4.160~2.h30", rls:"EULEROS-2.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-enhanced", rpm:"vim-enhanced~7.4.160~2.h30", rls:"EULEROS-2.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-filesystem", rpm:"vim-filesystem~7.4.160~2.h30", rls:"EULEROS-2.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-minimal", rpm:"vim-minimal~7.4.160~2.h30", rls:"EULEROS-2.0SP3"))) {
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
