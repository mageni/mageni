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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2022.1591");
  script_cve_id("CVE-2022-0213", "CVE-2022-0261", "CVE-2022-0318", "CVE-2022-0351", "CVE-2022-0359", "CVE-2022-0408", "CVE-2022-0413", "CVE-2022-0417", "CVE-2022-0443", "CVE-2022-0554", "CVE-2022-0572", "CVE-2022-0685", "CVE-2022-0714", "CVE-2022-0729");
  script_tag(name:"creation_date", value:"2022-04-25 07:33:45 +0000 (Mon, 25 Apr 2022)");
  script_version("2022-04-25T07:33:45+0000");
  script_tag(name:"last_modification", value:"2022-04-25 10:10:30 +0000 (Mon, 25 Apr 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-01-27 14:17:00 +0000 (Thu, 27 Jan 2022)");

  script_name("Huawei EulerOS: Security Advisory for vim (EulerOS-SA-2022-1591)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP8");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2022-1591");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2022-1591");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'vim' package(s) announced via the EulerOS-SA-2022-1591 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Stack-based Buffer Overflow in GitHub repository vim/vim prior to 8.2.(CVE-2022-0408)

Use After Free in Conda vim prior to 8.2.(CVE-2022-0443)

Use After Free in GitHub repository vim/vim prior to 8.2.(CVE-2022-0413)

Heap-based Buffer Overflow in Conda vim prior to 8.2.(CVE-2022-0417)

Heap-based Buffer Overflow in vim/vim prior to 8.2.(CVE-2022-0318)

vim is vulnerable to Heap-based Buffer Overflow(CVE-2022-0213)

Heap-based Buffer Overflow in GitHub repository vim/vim prior to 8.2.(CVE-2022-0359)

Access of Memory Location Before Start of Buffer in GitHub repository vim/vim prior to 8.2.(CVE-2022-0351)

Heap-based Buffer Overflow in GitHub repository vim/vim prior to 8.2.(CVE-2022-0261)

Heap-based Buffer Overflow in GitHub repository vim/vim prior to 8.2.(CVE-2022-0572)

Use of Out-of-range Pointer Offset in GitHub repository vim/vim prior to 8.2.4418.(CVE-2022-0685)

Use of Out-of-range Pointer Offset in GitHub repository vim/vim prior to 8.2.4440.(CVE-2022-0729)

Use of Out-of-range Pointer Offset in GitHub repository vim/vim prior to 8.2.(CVE-2022-0554)

Heap-based Buffer Overflow in GitHub repository vim/vim prior to 8.2.4436.(CVE-2022-0714)");

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

  if(!isnull(res = isrpmvuln(pkg:"vim-X11", rpm:"vim-X11~8.1.450~1.h22.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-common", rpm:"vim-common~8.1.450~1.h22.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-enhanced", rpm:"vim-enhanced~8.1.450~1.h22.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-filesystem", rpm:"vim-filesystem~8.1.450~1.h22.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-minimal", rpm:"vim-minimal~8.1.450~1.h22.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
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
