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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2023.1303");
  script_cve_id("CVE-2021-3778", "CVE-2021-3796", "CVE-2021-3872", "CVE-2021-3927", "CVE-2021-3928", "CVE-2021-3974", "CVE-2021-3984", "CVE-2021-4019", "CVE-2021-4069", "CVE-2021-4192", "CVE-2021-4193", "CVE-2022-0213", "CVE-2022-0351", "CVE-2022-0359", "CVE-2022-0413", "CVE-2022-0443", "CVE-2022-0714", "CVE-2022-0729", "CVE-2022-0943", "CVE-2022-1154", "CVE-2022-1620", "CVE-2022-1621", "CVE-2022-1629", "CVE-2022-1674", "CVE-2022-1733", "CVE-2022-1735", "CVE-2022-1796", "CVE-2022-1851", "CVE-2022-1897", "CVE-2022-1898", "CVE-2022-1942", "CVE-2022-1968", "CVE-2022-2000", "CVE-2022-2042", "CVE-2022-2124", "CVE-2022-2125", "CVE-2022-2126", "CVE-2022-2183", "CVE-2022-2206", "CVE-2022-2207", "CVE-2022-2208", "CVE-2022-2210", "CVE-2022-2257", "CVE-2022-2284", "CVE-2022-2285", "CVE-2022-2287", "CVE-2022-2289", "CVE-2022-2304", "CVE-2022-2345", "CVE-2022-2845");
  script_tag(name:"creation_date", value:"2023-01-31 04:21:24 +0000 (Tue, 31 Jan 2023)");
  script_version("2023-01-31T10:08:41+0000");
  script_tag(name:"last_modification", value:"2023-01-31 10:08:41 +0000 (Tue, 31 Jan 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-16 01:50:00 +0000 (Sat, 16 Jul 2022)");

  script_name("Huawei EulerOS: Security Advisory for vim (EulerOS-SA-2023-1303)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT\-3\.0\.2\.2");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2023-1303");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2023-1303");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'vim' package(s) announced via the EulerOS-SA-2023-1303 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"vim is vulnerable to Heap-based Buffer Overflow(CVE-2022-0213)

Heap-based Buffer Overflow in GitHub repository vim/vim prior to 8.2.(CVE-2022-0359)

Access of Memory Location Before Start of Buffer in GitHub repository vim/vim prior to 8.2.(CVE-2022-0351)

Use of Out-of-range Pointer Offset in GitHub repository vim/vim prior to 8.2.4440.(CVE-2022-0729)

Use After Free in GitHub repository vim/vim prior to 8.2.(CVE-2022-1968)

Out-of-bounds Write in GitHub repository vim/vim prior to 8.2.(CVE-2022-2000)

Heap-based Buffer Overflow in GitHub repository vim/vim prior to 8.2.(CVE-2022-2125)

Buffer Over-read in GitHub repository vim/vim prior to 8.2.(CVE-2022-2124)

Out-of-bounds Read in GitHub repository vim/vim prior to 8.2.(CVE-2022-2206)

Heap-based Buffer Overflow in GitHub repository vim/vim prior to 8.2.(CVE-2022-2207)

NULL Pointer Dereference in function vim_regexec_string at regexp.c:2733 in GitHub repository vim/vim prior to 8.2.4938. NULL Pointer Dereference in function vim_regexec_string at regexp.c:2733 allows attackers to cause a denial of service (application crash) via a crafted input.(CVE-2022-1674)

Out-of-bounds Read in GitHub repository vim/vim prior to 9.0.(CVE-2022-2287)

Heap-based Buffer Overflow in GitHub repository vim/vim prior to 9.0.(CVE-2022-2284)

Buffer Over-read in function find_next_quote in GitHub repository vim/vim prior to 8.2.4925. These vulnerabilities are capable of crashing software, Modify Memory, and possible remote
execution(CVE-2022-1629)

Use after free in utf_ptr2char in GitHub repository vim/vim prior to 8.2.4646.(CVE-2022-1154)

Heap-based Buffer Overflow in GitHub repository vim/vim prior to 8.2.4436.(CVE-2022-0714)

Use After Free in GitHub repository vim/vim prior to 8.2.4979.(CVE-2022-1796)

Heap-based Buffer Overflow occurs in vim in GitHub repository vim/vim prior to 8.2.4563.(CVE-2022-0943)

Use After Free in GitHub repository vim/vim prior to 8.2.(CVE-2022-2042)

Integer Overflow or Wraparound in GitHub repository vim/vim prior to 9.0.(CVE-2022-2285)

NULL Pointer Dereference in GitHub repository vim/vim prior to 8.2.5163.(CVE-2022-2208)

Use After Free in GitHub repository vim/vim prior to 8.2.(CVE-2022-0443)

Use After Free in GitHub repository vim/vim prior to 9.0.(CVE-2022-2289)

Use After Free in GitHub repository vim/vim prior to 8.2.(CVE-2022-0413)

NULL Pointer Dereference in function vim_regexec_string at regexp.c:2729 in GitHub repository vim/vim prior to 8.2.4901. NULL Pointer Dereference in function vim_regexec_string at regexp.c:2729 allows attackers to cause a denial of service (application crash) via a crafted input.(CVE-2022-1620)

Heap buffer overflow in vim_strncpy find_word in GitHub repository vim/vim prior to 8.2.4919. This vulnerability is capable of crashing software, Bypass Protection Mechanism, Modify Memory, and possible remote execution(CVE-2022-1621)

Out-of-bounds Write in GitHub ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'vim' package(s) on Huawei EulerOS Virtualization 3.0.2.2.");

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

if(release == "EULEROSVIRT-3.0.2.2") {

  if(!isnull(res = isrpmvuln(pkg:"vim-common", rpm:"vim-common~7.4.160~4.h33.eulerosv2r7", rls:"EULEROSVIRT-3.0.2.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-enhanced", rpm:"vim-enhanced~7.4.160~4.h33.eulerosv2r7", rls:"EULEROSVIRT-3.0.2.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-filesystem", rpm:"vim-filesystem~7.4.160~4.h33.eulerosv2r7", rls:"EULEROSVIRT-3.0.2.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-minimal", rpm:"vim-minimal~7.4.160~4.h33.eulerosv2r7", rls:"EULEROSVIRT-3.0.2.2"))) {
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
