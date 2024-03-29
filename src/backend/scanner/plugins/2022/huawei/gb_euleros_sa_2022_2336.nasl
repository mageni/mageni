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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2022.2336");
  script_cve_id("CVE-2022-1720", "CVE-2022-1725", "CVE-2022-1733", "CVE-2022-1735", "CVE-2022-1771", "CVE-2022-1785", "CVE-2022-1796", "CVE-2022-1851", "CVE-2022-1897", "CVE-2022-1898", "CVE-2022-1927", "CVE-2022-1942", "CVE-2022-1968", "CVE-2022-2000", "CVE-2022-2042", "CVE-2022-2124", "CVE-2022-2125", "CVE-2022-2126", "CVE-2022-2175", "CVE-2022-2183", "CVE-2022-2206", "CVE-2022-2207", "CVE-2022-2208", "CVE-2022-2210", "CVE-2022-2257", "CVE-2022-2264", "CVE-2022-2284", "CVE-2022-2285", "CVE-2022-2286", "CVE-2022-2287", "CVE-2022-2289", "CVE-2022-2304", "CVE-2022-2343", "CVE-2022-2344", "CVE-2022-2345", "CVE-2022-2522");
  script_tag(name:"creation_date", value:"2022-09-14 04:42:02 +0000 (Wed, 14 Sep 2022)");
  script_version("2022-09-15T10:11:06+0000");
  script_tag(name:"last_modification", value:"2022-09-15 10:11:06 +0000 (Thu, 15 Sep 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-07 02:38:00 +0000 (Thu, 07 Jul 2022)");

  script_name("Huawei EulerOS: Security Advisory for vim (EulerOS-SA-2022-2336)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP9");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2022-2336");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2022-2336");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'vim' package(s) announced via the EulerOS-SA-2022-2336 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Heap-based Buffer Overflow in GitHub repository vim/vim prior to 9.0.0060.(CVE-2022-2522)

Stack-based Buffer Overflow in GitHub repository vim/vim prior to 9.0.(CVE-2022-2304)

Heap-based Buffer Overflow in GitHub repository vim/vim prior to 9.0.0045.(CVE-2022-2344)

Use After Free in GitHub repository vim/vim prior to 9.0.0046.(CVE-2022-2345)

Heap-based Buffer Overflow in GitHub repository vim/vim prior to 9.0.0044.(CVE-2022-2343)

Integer Overflow or Wraparound in GitHub repository vim/vim prior to 9.0.(CVE-2022-2285)

Heap-based Buffer Overflow in GitHub repository vim/vim prior to 9.0.(CVE-2022-2284)

Heap-based Buffer Overflow in GitHub repository vim/vim prior to 8.2.(CVE-2022-2207)

NULL Pointer Dereference in GitHub repository vim/vim prior to 8.2.5163.(CVE-2022-2208)

Out-of-bounds Read in GitHub repository vim/vim prior to 9.0.(CVE-2022-2287)

Use After Free in GitHub repository vim/vim prior to 9.0.(CVE-2022-2289)

Out-of-bounds Read in GitHub repository vim/vim prior to 9.0.(CVE-2022-2286)

Out-of-bounds Read in GitHub repository vim/vim prior to 9.0.(CVE-2022-2257)

Heap-based Buffer Overflow in GitHub repository vim/vim prior to 9.0.(CVE-2022-2264)

Out-of-bounds Write in GitHub repository vim/vim prior to 8.2.(CVE-2022-2210)

Buffer Over-read in GitHub repository vim/vim prior to 8.2.(CVE-2022-2175)

Out-of-bounds Read in GitHub repository vim/vim prior to 8.2.(CVE-2022-2126)

Buffer Over-read in GitHub repository vim/vim prior to 8.2.(CVE-2022-2124)

Heap-based Buffer Overflow in GitHub repository vim/vim prior to 8.2.(CVE-2022-2125)

Out-of-bounds Read in GitHub repository vim/vim prior to 8.2.(CVE-2022-2183)

Out-of-bounds Read in GitHub repository vim/vim prior to 8.2.(CVE-2022-2206)

Use After Free in GitHub repository vim/vim prior to 8.2.(CVE-2022-1968)

Out-of-bounds Write in GitHub repository vim/vim prior to 8.2.(CVE-2022-1897)

Use After Free in GitHub repository vim/vim prior to 8.2.4979.(CVE-2022-1796)

Out-of-bounds Read in GitHub repository vim/vim prior to 8.2.(CVE-2022-1851)

Buffer Over-read in GitHub repository vim/vim prior to 8.2.(CVE-2022-1927)

Out-of-bounds Write in GitHub repository vim/vim prior to 8.2.4977.(CVE-2022-1785)

Uncontrolled Recursion in GitHub repository vim/vim prior to 8.2.4975.(CVE-2022-1771)

NULL Pointer Dereference in GitHub repository vim/vim prior to 8.2.4959.(CVE-2022-1725)

Buffer Over-read in function grab_file_name in GitHub repository vim/vim prior to 8.2.4956. This vulnerability is capable of crashing the software, memory modification, and possible remote execution.(CVE-2022-1720)

Classic Buffer Overflow in GitHub repository vim/vim prior to 8.2.4969.(CVE-2022-1735)

Heap-based Buffer Overflow in GitHub repository vim/vim prior to 8.2.4968.(CVE-2022-1733)

Out-of-bounds Write in GitHub repository vim/vim prior to 8.2.(CVE-2022-2000)

Use After Free in GitHub repository vim/vim prior to ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'vim' package(s) on Huawei EulerOS V2.0SP9.");

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

if(release == "EULEROS-2.0SP9") {

  if(!isnull(res = isrpmvuln(pkg:"vim-common", rpm:"vim-common~8.2~1.h5.r34.eulerosv2r9", rls:"EULEROS-2.0SP9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-enhanced", rpm:"vim-enhanced~8.2~1.h5.r34.eulerosv2r9", rls:"EULEROS-2.0SP9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-filesystem", rpm:"vim-filesystem~8.2~1.h5.r34.eulerosv2r9", rls:"EULEROS-2.0SP9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-minimal", rpm:"vim-minimal~8.2~1.h5.r34.eulerosv2r9", rls:"EULEROS-2.0SP9"))) {
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
