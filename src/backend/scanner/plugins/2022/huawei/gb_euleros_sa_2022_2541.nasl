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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2022.2541");
  script_cve_id("CVE-2021-3927", "CVE-2021-3928", "CVE-2021-3974", "CVE-2021-3984", "CVE-2021-4019", "CVE-2021-4069", "CVE-2021-4192", "CVE-2021-4193", "CVE-2022-0213", "CVE-2022-0319", "CVE-2022-0351", "CVE-2022-0359", "CVE-2022-0413", "CVE-2022-0443", "CVE-2022-0714", "CVE-2022-0729", "CVE-2022-0943", "CVE-2022-1154", "CVE-2022-1616", "CVE-2022-1620", "CVE-2022-1621", "CVE-2022-1629", "CVE-2022-1674", "CVE-2022-1733", "CVE-2022-1735", "CVE-2022-1796", "CVE-2022-1851", "CVE-2022-1897", "CVE-2022-1898", "CVE-2022-1942", "CVE-2022-1968", "CVE-2022-2000", "CVE-2022-2042");
  script_tag(name:"creation_date", value:"2022-10-10 07:55:28 +0000 (Mon, 10 Oct 2022)");
  script_version("2022-10-10T10:12:14+0000");
  script_tag(name:"last_modification", value:"2022-10-10 10:12:14 +0000 (Mon, 10 Oct 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-06-17 18:07:00 +0000 (Fri, 17 Jun 2022)");

  script_name("Huawei EulerOS: Security Advisory for vim (EulerOS-SA-2022-2541)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT\-3\.0\.6\.6");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2022-2541");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2022-2541");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'vim' package(s) announced via the EulerOS-SA-2022-2541 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"vim is vulnerable to Heap-based Buffer Overflow(CVE-2021-3927)

vim is vulnerable to Heap-based Buffer Overflow(CVE-2021-3928)

vim is vulnerable to Use After Free(CVE-2021-3974)

vim is vulnerable to Heap-based Buffer Overflow(CVE-2021-3984)

vim is vulnerable to Heap-based Buffer Overflow(CVE-2021-4019)

vim is vulnerable to Use After Free(CVE-2021-4069)

vim is vulnerable to Use After Free(CVE-2021-4192)

vim is vulnerable to Out-of-bounds Read(CVE-2021-4193)

A flaw was found in vim. The vulnerability occurs due to Illegal memory access and leads to a use-after-free vulnerability in the find_pattern_in_path function. This flaw allows an attacker to input a specially crafted file, leading to a crash or code execution.(CVE-2022-1898)

A flaw was found in vim. The vulnerability occurs due to Illegal memory access and leads to an out-of-bounds write vulnerability in the vim_regsub_both function. This flaw allows an attacker to input a specially crafted file, leading to a crash or code execution.(CVE-2022-1897)

A flaw was found in vim. The vulnerability occurs due to Illegal memory access and leads to a use after free vulnerability. This flaw allows an attacker to input a specially crafted file, leading to a crash or code execution.(CVE-2022-1796)

Classic Buffer Overflow in GitHub repository vim/vim prior to 8.2.4969.(CVE-2022-1735)

Heap-based Buffer Overflow in GitHub repository vim/vim prior to 8.2.4968.(CVE-2022-1733)

A NULL pointer dereference flaw was found in vim's vim_regexec_string() function in regexp.c file. The issue occurs when the function tries to match the buffer with an invalid pattern. This flaw allows an attacker to trick a user into opening a specially crafted file, triggering a NULL pointer dereference that causes an application to crash, leading to a denial of service.(CVE-2022-1674)

A flaw was found in vim, where it is vulnerable to a buffer over-read in the find_next_quote function. This flaw allows a specially crafted file to crash software, modify memory and possibly perform remote execution when opened in vim.(CVE-2022-1629)

A flaw was found in vim, where it is vulnerable to a heap buffer overflow in the vim_strncpy find_word function. This flaw allows a specially crafted file to crash software, modify memory and possibly perform remote execution when opened in vim.(CVE-2022-1621)

A flaw was found in vim, which is vulnerable to a NULL pointer dereference in vim_regexec_string() of the regexp.c function. This flaw allows a specially crafted file to crash software when opened in vim.(CVE-2022-1620)

A flaw was found in vim, which is vulnerable to a heap-buffer-overflow in append_command of the src/ex_docmd.c function. This flaw allows a specially crafted file to crash software, modify memory, or execute code when opened in vim.(CVE-2022-1616)

A flaw was found in vim. The vulnerability occurs due to Illegal memory access and leads to a ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'vim' package(s) on Huawei EulerOS Virtualization 3.0.6.6.");

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

if(release == "EULEROSVIRT-3.0.6.6") {

  if(!isnull(res = isrpmvuln(pkg:"vim-X11", rpm:"vim-X11~7.4.160~4.h26.eulerosv2r7", rls:"EULEROSVIRT-3.0.6.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-common", rpm:"vim-common~7.4.160~4.h26.eulerosv2r7", rls:"EULEROSVIRT-3.0.6.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-enhanced", rpm:"vim-enhanced~7.4.160~4.h26.eulerosv2r7", rls:"EULEROSVIRT-3.0.6.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-filesystem", rpm:"vim-filesystem~7.4.160~4.h26.eulerosv2r7", rls:"EULEROSVIRT-3.0.6.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-minimal", rpm:"vim-minimal~7.4.160~4.h26.eulerosv2r7", rls:"EULEROSVIRT-3.0.6.6"))) {
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
