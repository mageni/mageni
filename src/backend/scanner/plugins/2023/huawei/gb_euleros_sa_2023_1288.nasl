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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2023.1288");
  script_cve_id("CVE-2021-23437", "CVE-2021-25290", "CVE-2021-28675", "CVE-2021-28676", "CVE-2021-28677", "CVE-2021-34552", "CVE-2022-22815", "CVE-2022-22816", "CVE-2022-22817");
  script_tag(name:"creation_date", value:"2023-01-31 04:21:24 +0000 (Tue, 31 Jan 2023)");
  script_version("2023-01-31T10:08:41+0000");
  script_tag(name:"last_modification", value:"2023-01-31 10:08:41 +0000 (Tue, 31 Jan 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-01-19 14:10:00 +0000 (Wed, 19 Jan 2022)");

  script_name("Huawei EulerOS: Security Advisory for python-pillow (EulerOS-SA-2023-1288)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT\-3\.0\.2\.2");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2023-1288");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2023-1288");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'python-pillow' package(s) announced via the EulerOS-SA-2023-1288 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"path_getbbox in path.c in Pillow before 9.0.0 improperly initializes ImagePath.Path.(CVE-2022-22815)

PIL.ImageMath.eval in Pillow before 9.0.0 allows evaluation of arbitrary expressions, such as ones that use the Python exec method.(CVE-2022-22817)

path_getbbox in path.c in Pillow before 9.0.0 has a buffer over-read during initialization of ImagePath.Path.(CVE-2022-22816)

Pillow through 8.2.0 and PIL (aka Python Imaging Library) through 1.1.7 allow an attacker to pass controlled parameters directly into a convert function to trigger a buffer overflow in Convert.c.(CVE-2021-34552)

An issue was discovered in Pillow before 8.1.1. In TiffDecode.c, there is a negative-offset memcpy with an invalid size.(CVE-2021-25290)

DOS in PsdImagePlugin(CVE-2021-28675)

An issue was discovered in Pillow before 8.2.0. For FLI data, FliDecode did not properly check that the block advance was non-zero, potentially leading to an infinite loop on load.(CVE-2021-28676)

An issue was discovered in Pillow before 8.2.0. For EPS data, the readline implementation used in EPSImageFile has to deal with any combination of \r and \n as line endings. It used an accidentally quadratic method of accumulating lines while looking for a line ending. A malicious EPS file could use this to perform a DoS of Pillow in the open phase, before an image was accepted for opening.(CVE-2021-28677)

The package pillow from 0 and before 8.3.2 are vulnerable to Regular Expression Denial of Service (ReDoS) via the getrgb function.(CVE-2021-23437)");

  script_tag(name:"affected", value:"'python-pillow' package(s) on Huawei EulerOS Virtualization 3.0.2.2.");

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

  if(!isnull(res = isrpmvuln(pkg:"python-pillow", rpm:"python-pillow~2.0.0~19.h15.gitd1c6db8.eulerosv2r7", rls:"EULEROSVIRT-3.0.2.2"))) {
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
