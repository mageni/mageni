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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2019.1421");
  script_version("2020-01-23T11:44:09+0000");
  script_cve_id("CVE-2011-2501", "CVE-2011-2690", "CVE-2011-2691", "CVE-2011-2692", "CVE-2011-3026", "CVE-2011-3048", "CVE-2015-7981", "CVE-2015-8472", "CVE-2015-8540");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-01-23 11:44:09 +0000 (Thu, 23 Jan 2020)");
  script_tag(name:"creation_date", value:"2020-01-23 11:44:09 +0000 (Thu, 23 Jan 2020)");
  script_name("Huawei EulerOS: Security Advisory for libpng (EulerOS-SA-2019-1421)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT-3\.0\.1\.0");

  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1421");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS
  'libpng' package(s) announced via the EulerOS-SA-2019-1421 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The png_set_text_2 function in pngset.c in libpng 1.0.x before 1.0.59, 1.2.x before 1.2.49, 1.4.x before 1.4.11, and 1.5.x before 1.5.10 allows remote attackers to cause a denial of service (crash) or execute arbitrary code via a crafted text chunk in a PNG image file, which triggers a memory allocation failure that is not properly handled, leading to a heap-based buffer overflow.(CVE-2011-3048)

The png_handle_sCAL function in pngrutil.c in libpng 1.0.x before 1.0.55, 1.2.x before 1.2.45, 1.4.x before 1.4.8, and 1.5.x before 1.5.4 does not properly handle invalid sCAL chunks, which allows remote attackers to cause a denial of service (memory corruption and application crash) or possibly have unspecified other impact via a crafted PNG image that triggers the reading of uninitialized memory.(CVE-2011-2692)

It was discovered that the png_get_PLTE() and png_set_PLTE() functions of libpng did not correctly calculate the maximum palette sizes for bit depths of less than 8. In case an application tried to use these functions in combination with properly calculated palette sizes, this could lead to a buffer overflow or out-of-bounds reads. An attacker could exploit this to cause a crash or potentially execute arbitrary code by tricking an unsuspecting user into processing a specially crafted PNG image. However, the exact impact is dependent on the application using the library.(CVE-2015-8472)

The png_err function in pngerror.c in libpng 1.0.x before 1.0.55, 1.2.x before 1.2.45, 1.4.x before 1.4.8, and 1.5.x before 1.5.4 makes a function call using a NULL pointer argument instead of an empty-string argument, which allows remote attackers to cause a denial of service (application crash) via a crafted PNG image.(CVE-2011-2691)

Integer underflow in the png_check_keyword function in pngwutil.c in libpng 0.90 through 0.99, 1.0.x before 1.0.66, 1.1.x and 1.2.x before 1.2.56, 1.3.x and 1.4.x before 1.4.19, and 1.5.x before 1.5.26 allows remote attackers to have unspecified impact via a space character as a keyword in a PNG image, which triggers an out-of-bounds read.(CVE-2015-8540)

Integer overflow in libpng, as used in Google Chrome before 17.0.963.56, allows remote attackers to cause a denial of service or possibly have unspecified other impact via unknown vectors that trigger an integer truncation.(CVE-2011-3026)

An array-indexing error was discovered in the png_convert_to_rfc1123() function of libpng. An attacker could possibly use this flaw to cause an out-of-bounds read by tricking an unsuspecting user into processing a specially crafted PNG image.(CVE-2015-7981)

Buffer overflow ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'libpng' package(s) on Huawei EulerOS Virtualization 3.0.1.0.");

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

if(release == "EULEROSVIRT-3.0.1.0") {

  if(!isnull(res = isrpmvuln(pkg:"libpng", rpm:"libpng~1.5.13~7.1.h2.eulerosv2r7", rls:"EULEROSVIRT-3.0.1.0"))) {
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