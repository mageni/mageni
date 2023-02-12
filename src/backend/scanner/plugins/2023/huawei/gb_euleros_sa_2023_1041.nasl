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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2023.1041");
  script_cve_id("CVE-2022-40303", "CVE-2022-40304");
  script_tag(name:"creation_date", value:"2023-01-09 15:11:01 +0000 (Mon, 09 Jan 2023)");
  script_version("2023-01-10T10:12:01+0000");
  script_tag(name:"last_modification", value:"2023-01-10 10:12:01 +0000 (Tue, 10 Jan 2023)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-11-30 16:26:00 +0000 (Wed, 30 Nov 2022)");

  script_name("Huawei EulerOS: Security Advisory for libxml2 (EulerOS-SA-2023-1041)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP11\-X86_64");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2023-1041");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2023-1041");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'libxml2' package(s) announced via the EulerOS-SA-2023-1041 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A flaw was found in libxml2. When a reference cycle is detected in the XML entity cleanup function the XML entity data can be stored in a dictionary. In this case, the dictionary becomes corrupted resulting in logic errors, including memory errors like double free.(CVE-2022-40304)

A flaw was found in libxml2. Parsing a XML document with the XML_PARSE_HUGE option enabled can result in an integer overflow because safety checks were missing in some functions. Also, the xmlParseEntityValue function didn t have any length limitation.(CVE-2022-40303)");

  script_tag(name:"affected", value:"'libxml2' package(s) on Huawei EulerOS V2.0SP11(x86_64).");

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

if(release == "EULEROS-2.0SP11-x86_64") {

  if(!isnull(res = isrpmvuln(pkg:"libxml2", rpm:"libxml2~2.9.12~5.h11.eulerosv2r11", rls:"EULEROS-2.0SP11-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-libxml2", rpm:"python3-libxml2~2.9.12~5.h11.eulerosv2r11", rls:"EULEROS-2.0SP11-x86_64"))) {
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
