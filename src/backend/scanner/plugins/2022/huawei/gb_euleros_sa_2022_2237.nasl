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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2022.2237");
  script_cve_id("CVE-2022-1621", "CVE-2022-1629", "CVE-2022-1674", "CVE-2022-1733", "CVE-2022-1735", "CVE-2022-1771", "CVE-2022-1785", "CVE-2022-1796", "CVE-2022-1851", "CVE-2022-1897", "CVE-2022-1898", "CVE-2022-1927", "CVE-2022-1942", "CVE-2022-1968", "CVE-2022-2000");
  script_tag(name:"creation_date", value:"2022-08-18 04:37:33 +0000 (Thu, 18 Aug 2022)");
  script_version("2022-08-18T04:37:33+0000");
  script_tag(name:"last_modification", value:"2022-08-18 04:37:33 +0000 (Thu, 18 Aug 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-06-08 16:08:00 +0000 (Wed, 08 Jun 2022)");

  script_name("Huawei EulerOS: Security Advisory for vim (EulerOS-SA-2022-2237)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP8");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2022-2237");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2022-2237");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'vim' package(s) announced via the EulerOS-SA-2022-2237 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Uncontrolled Recursion in GitHub repository vim/vim prior to 8.2.4975.(CVE-2022-1771)

Classic Buffer Overflow in GitHub repository vim/vim prior to 8.2.4969.(CVE-2022-1735)

Out-of-bounds Write in GitHub repository vim/vim prior to 8.2.4977.(CVE-2022-1785)

Use After Free in GitHub repository vim/vim prior to 8.2.4979.(CVE-2022-1796)

Out-of-bounds Write in GitHub repository vim/vim prior to 8.2.(CVE-2022-2000)

Use After Free in GitHub repository vim/vim prior to 8.2.(CVE-2022-1968)

Buffer Over-read in GitHub repository vim/vim prior to 8.2.(CVE-2022-1927)

Use After Free in GitHub repository vim/vim prior to 8.2.(CVE-2022-1898)

Out-of-bounds Write in GitHub repository vim/vim prior to 8.2.(CVE-2022-1897)

Out-of-bounds Read in GitHub repository vim/vim prior to 8.2.(CVE-2022-1851)

Heap-based Buffer Overflow in GitHub repository vim/vim prior to 8.2.(CVE-2022-1942)

NULL Pointer Dereference in function vim_regexec_string at regexp.c:2733 in GitHub repository vim/vim prior to 8.2.4938. NULL Pointer Dereference in function vim_regexec_string at regexp.c:2733 allows attackers to cause a denial of service (application crash) via a crafted input.(CVE-2022-1674)

Heap-based Buffer Overflow in GitHub repository vim/vim prior to 8.2.4968.(CVE-2022-1733)

Buffer Over-read in function find_next_quote in GitHub repository vim/vim prior to 8.2.4925. These vulnerabilities are capable of crashing software, Modify Memory, and possible remote execution(CVE-2022-1629)

Heap buffer overflow in vim_strncpy find_word in GitHub repository vim/vim prior to 8.2.4919. This vulnerability is capable of crashing software, Bypass Protection Mechanism, Modify Memory, and possible remote execution(CVE-2022-1621)");

  script_tag(name:"affected", value:"'vim' package(s) on Huawei EulerOS V2.0SP8.");

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

if(release == "EULEROS-2.0SP8") {

  if(!isnull(res = isrpmvuln(pkg:"vim-X11", rpm:"vim-X11~8.1.450~1.h31.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-common", rpm:"vim-common~8.1.450~1.h31.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-enhanced", rpm:"vim-enhanced~8.1.450~1.h31.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-filesystem", rpm:"vim-filesystem~8.1.450~1.h31.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-minimal", rpm:"vim-minimal~8.1.450~1.h31.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
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
