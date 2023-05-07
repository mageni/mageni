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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2023.1684");
  script_cve_id("CVE-2022-3296", "CVE-2022-3297", "CVE-2022-3324", "CVE-2022-3352", "CVE-2022-3520", "CVE-2022-3705", "CVE-2022-4141", "CVE-2022-4292", "CVE-2022-4293", "CVE-2023-0049", "CVE-2023-0051", "CVE-2023-0288");
  script_tag(name:"creation_date", value:"2023-04-27 04:14:00 +0000 (Thu, 27 Apr 2023)");
  script_version("2023-04-27T12:17:38+0000");
  script_tag(name:"last_modification", value:"2023-04-27 12:17:38 +0000 (Thu, 27 Apr 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-12-06 12:26:00 +0000 (Tue, 06 Dec 2022)");

  script_name("Huawei EulerOS: Security Advisory for vim (EulerOS-SA-2023-1684)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT\-2\.9\.0");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2023-1684");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2023-1684");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'vim' package(s) announced via the EulerOS-SA-2023-1684 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A vulnerability was found in vim and classified as problematic. Affected by this issue is the function qf_update_buffer of the file quickfix.c of the component autocmd Handler. The manipulation leads to use after free. The attack may be launched remotely. Upgrading to version 9.0.0805 is able to address this issue. The name of the patch is d0fab10ed2a86698937e3c3fed2f10bd9bb5e731. It is recommended to upgrade the affected component. The identifier of this vulnerability is VDB-212324.(CVE-2022-3705)

Stack-based Buffer Overflow in GitHub repository vim/vim prior to 9.0.0598.(CVE-2022-3324)

Use After Free in GitHub repository vim/vim prior to 9.0.0614.(CVE-2022-3352)

Use After Free in GitHub repository vim/vim prior to 9.0.0579.(CVE-2022-3297)

Stack-based Buffer Overflow in GitHub repository vim/vim prior to 9.0.0577.(CVE-2022-3296)

Heap-based Buffer Overflow in GitHub repository vim/vim prior to 9.0.1189.(CVE-2023-0288)

Out-of-bounds Read in GitHub repository vim/vim prior to 9.0.1143.(CVE-2023-0049)

Heap-based Buffer Overflow in GitHub repository vim/vim prior to 9.0.1144.(CVE-2023-0051)

Heap-based Buffer Overflow in GitHub repository vim/vim prior to 9.0.0765.(CVE-2022-3520)

Floating Point Comparison with Incorrect Operator in GitHub repository vim/vim prior to 9.0.0804.(CVE-2022-4293)

Use After Free in GitHub repository vim/vim prior to 9.0.0882.(CVE-2022-4292)

Heap based buffer overflow in vim/vim 9.0.0946 and below by allowing an attacker to CTRL-W gf in the expression used in the RHS of the substitute command.(CVE-2022-4141)");

  script_tag(name:"affected", value:"'vim' package(s) on Huawei EulerOS Virtualization release 2.9.0.");

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

if(release == "EULEROSVIRT-2.9.0") {

  if(!isnull(res = isrpmvuln(pkg:"vim-common", rpm:"vim-common~8.2~1.h5.r49.eulerosv2r9", rls:"EULEROSVIRT-2.9.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-enhanced", rpm:"vim-enhanced~8.2~1.h5.r49.eulerosv2r9", rls:"EULEROSVIRT-2.9.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-filesystem", rpm:"vim-filesystem~8.2~1.h5.r49.eulerosv2r9", rls:"EULEROSVIRT-2.9.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-minimal", rpm:"vim-minimal~8.2~1.h5.r49.eulerosv2r9", rls:"EULEROSVIRT-2.9.0"))) {
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
