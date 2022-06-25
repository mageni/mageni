# Copyright (C) 2020 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2019.2627");
  script_version("2020-01-23T13:10:10+0000");
  script_cve_id("CVE-2015-7995", "CVE-2016-1683", "CVE-2016-1684", "CVE-2016-4607", "CVE-2016-4608", "CVE-2016-4609", "CVE-2016-4610", "CVE-2019-18197");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-01-23 13:10:10 +0000 (Thu, 23 Jan 2020)");
  script_tag(name:"creation_date", value:"2020-01-23 13:10:10 +0000 (Thu, 23 Jan 2020)");
  script_name("Huawei EulerOS: Security Advisory for libxslt (EulerOS-SA-2019-2627)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS-2\.0SP3");

  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-2627");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS
  'libxslt' package(s) announced via the EulerOS-SA-2019-2627 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The xsltStylePreCompute function in preproc.c in libxslt 1.1.28 does not check if the parent node is an element, which allows attackers to cause a denial of service via a crafted XML file, related to a 'type confusion' issue.(CVE-2015-7995)

numbers.c in libxslt before 1.1.29, as used in Google Chrome before 51.0.2704.63, mishandles namespace nodes, which allows remote attackers to cause a denial of service (out-of-bounds heap memory access) or possibly have unspecified other impact via a crafted document.(CVE-2016-1683)

numbers.c in libxslt before 1.1.29, as used in Google Chrome before 51.0.2704.63, mishandles the i format token for xsl:number data, which allows remote attackers to cause a denial of service (integer overflow or resource consumption) or possibly have unspecified other impact via a crafted document.(CVE-2016-1684)

libxslt in Apple iOS before 9.3.3, OS X before 10.11.6, iTunes before 12.4.2 on Windows, iCloud before 5.2.1 on Windows, tvOS before 9.2.2, and watchOS before 2.2.2 allows remote attackers to cause a denial of service (memory corruption) or possibly have unspecified other impact via unknown vectors, a different vulnerability than CVE-2016-4608, CVE-2016-4609, CVE-2016-4610, and CVE-2016-4612.(CVE-2016-4607)

libxslt in Apple iOS before 9.3.3, OS X before 10.11.6, iTunes before 12.4.2 on Windows, iCloud before 5.2.1 on Windows, tvOS before 9.2.2, and watchOS before 2.2.2 allows remote attackers to cause a denial of service (memory corruption) or possibly have unspecified other impact via unknown vectors, a different vulnerability than CVE-2016-4607, CVE-2016-4609, CVE-2016-4610, and CVE-2016-4612.(CVE-2016-4608)

libxslt in Apple iOS before 9.3.3, OS X before 10.11.6, iTunes before 12.4.2 on Windows, iCloud before 5.2.1 on Windows, tvOS before 9.2.2, and watchOS before 2.2.2 allows remote attackers to cause a denial of service (memory corruption) or possibly have unspecified other impact via unknown vectors, a different vulnerability than CVE-2016-4607, CVE-2016-4608, CVE-2016-4610, and CVE-2016-4612.(CVE-2016-4609)

libxslt in Apple iOS before 9.3.3, OS X before 10.11.6, iTunes before 12.4.2 on Windows, iCloud before 5.2.1 on Windows, tvOS before 9.2.2, and watchOS before 2.2.2 allows remote attackers to cause a denial of service (memory corruption) or possibly have unspecified other impact via unknown vectors, a different vulnerability than CVE-2016-4607, CVE-2016-4608, CVE-2016-4609, and CVE-2016-4612.(CVE-2016-4610)

In xsltCopyText in transform.c in libxslt 1.1.33, a pointer variable isn't reset under certain circumstances. If the relevant memory area happened to be freed and reused in a certain way, a bounds check could fail and memory outside a buffer could be written to, or uninitialized data could be disclosed.(CVE-2019-18197)");

  script_tag(name:"affected", value:"'libxslt' package(s) on Huawei EulerOS V2.0SP3.");

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

  if(!isnull(res = isrpmvuln(pkg:"libxslt", rpm:"libxslt~1.1.28~5.h6", rls:"EULEROS-2.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxslt-devel", rpm:"libxslt-devel~1.1.28~5.h6", rls:"EULEROS-2.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxslt-python", rpm:"libxslt-python~1.1.28~5.h6", rls:"EULEROS-2.0SP3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if (__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);