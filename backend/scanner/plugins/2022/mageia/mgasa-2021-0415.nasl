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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2021.0415");
  script_cve_id("CVE-2021-32815", "CVE-2021-34334", "CVE-2021-34335", "CVE-2021-37615", "CVE-2021-37616", "CVE-2021-37618", "CVE-2021-37619", "CVE-2021-37620", "CVE-2021-37621", "CVE-2021-37622", "CVE-2021-37623");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-08-20 15:02:00 +0000 (Fri, 20 Aug 2021)");

  script_name("Mageia: Security Advisory (MGASA-2021-0415)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2021-0415");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2021-0415.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=29371");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5043-1");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/FMDT4PJB7P43WSOM3TRQIY3J33BAFVVE/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'exiv2' package(s) announced via the MGASA-2021-0415 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The updated exiv2 packages fix security vulnerabilities:

An assertion failure is triggered when Exiv2 is used to modify the metadata
of a crafted image file. An attacker could potentially exploit the
vulnerability to cause a denial of service, if they can trick the victim
into running Exiv2 on a crafted image file (CVE-2021-32815).

An infinite loop is triggered when Exiv2 is used to read the metadata of a
crafted image file. An attacker could potentially exploit the vulnerability
to cause a denial of service, if they can trick the victim into running
Exiv2 on a crafted image file (CVE-2021-34334).

A floating point exception (FPE) due to an integer divide by zero was found
in Exiv2 versions v0.27.4 and earlier. The FPE is triggered when Exiv2 is
used to print the metadata of a crafted image file. An attacker could
potentially exploit the vulnerability to cause a denial of service, if they
can trick the victim into running Exiv2 on a crafted image file
(CVE-2021-34335).

A null pointer dereference was found in Exiv2 versions v0.27.4 and earlier.
The null pointer dereference is triggered when Exiv2 is used to print the
metadata of a crafted image file. An attacker could potentially exploit the
vulnerability to cause a denial of service, if they can trick the victim
into running Exiv2 on a crafted image file (CVE-2021-37615, CVE-2021-37616).

An out-of-bounds read was found in Exiv2 versions v0.27.4 and earlier. The
out-of-bounds read is triggered when Exiv2 is used to print the metadata
of a crafted image file. An attacker could potentially exploit
thevulnerability to cause a denial of service, if they can trick the victim
into running Exiv2 on a crafted image file (CVE-2021-37618, CVE-2021-37619,
CVE-2021-37620).

An infinite loop was found in Exiv2 versions v0.27.4 and earlier. The
infinite loop is triggered when Exiv2 is used to print the metadata of a
crafted image file. An attacker could potentially exploit the vulnerability
to cause a denial of service, if they can trick the victim into running Exiv2
on a crafted image file (CVE-2021-37621, CVE-2021-37622, CVE-2021-37623).");

  script_tag(name:"affected", value:"'exiv2' package(s) on Mageia 8.");

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

if(release == "MAGEIA8") {

  if(!isnull(res = isrpmvuln(pkg:"exiv2", rpm:"exiv2~0.27.3~1.3.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"exiv2-doc", rpm:"exiv2-doc~0.27.3~1.3.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64exiv2-devel", rpm:"lib64exiv2-devel~0.27.3~1.3.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64exiv2_27", rpm:"lib64exiv2_27~0.27.3~1.3.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libexiv2-devel", rpm:"libexiv2-devel~0.27.3~1.3.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libexiv2_27", rpm:"libexiv2_27~0.27.3~1.3.mga8", rls:"MAGEIA8"))) {
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
