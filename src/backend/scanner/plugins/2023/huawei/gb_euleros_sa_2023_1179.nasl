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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2023.1179");
  script_cve_id("CVE-2022-3099", "CVE-2022-3134", "CVE-2022-3234", "CVE-2022-3235", "CVE-2022-3256", "CVE-2022-3296", "CVE-2022-3297", "CVE-2022-3324", "CVE-2022-3352");
  script_tag(name:"creation_date", value:"2023-01-12 04:15:41 +0000 (Thu, 12 Jan 2023)");
  script_version("2023-01-12T10:12:15+0000");
  script_tag(name:"last_modification", value:"2023-01-12 10:12:15 +0000 (Thu, 12 Jan 2023)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-09-30 23:35:00 +0000 (Fri, 30 Sep 2022)");

  script_name("Huawei EulerOS: Security Advisory for vim (EulerOS-SA-2023-1179)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT\-2\.10\.0");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2023-1179");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2023-1179");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'vim' package(s) announced via the EulerOS-SA-2023-1179 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Use After Free in GitHub repository vim/vim prior to 9.0.0579.(CVE-2022-3297)

Stack-based Buffer Overflow in GitHub repository vim/vim prior to 9.0.0577.(CVE-2022-3296)

Stack-based Buffer Overflow in GitHub repository vim/vim prior to 9.0.0598.(CVE-2022-3324)

Use After Free in GitHub repository vim/vim prior to 9.0.0614.(CVE-2022-3352)

Use After Free in GitHub repository vim/vim prior to 9.0.0530.(CVE-2022-3256)

Heap-based Buffer Overflow in GitHub repository vim/vim prior to 9.0.0483.(CVE-2022-3234)

Use After Free in GitHub repository vim/vim prior to 9.0.0490.(CVE-2022-3235)

Use After Free in GitHub repository vim/vim prior to 9.0.0389.(CVE-2022-3134)

Use After Free in GitHub repository vim/vim prior to 9.0.0360.(CVE-2022-3099)");

  script_tag(name:"affected", value:"'vim' package(s) on Huawei EulerOS Virtualization release 2.10.0.");

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

if(release == "EULEROSVIRT-2.10.0") {

  if(!isnull(res = isrpmvuln(pkg:"vim-common", rpm:"vim-common~8.2~1.h60.eulerosv2r10", rls:"EULEROSVIRT-2.10.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-enhanced", rpm:"vim-enhanced~8.2~1.h60.eulerosv2r10", rls:"EULEROSVIRT-2.10.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-filesystem", rpm:"vim-filesystem~8.2~1.h60.eulerosv2r10", rls:"EULEROSVIRT-2.10.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-minimal", rpm:"vim-minimal~8.2~1.h60.eulerosv2r10", rls:"EULEROSVIRT-2.10.0"))) {
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
