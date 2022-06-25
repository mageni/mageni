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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2018.0455");
  script_cve_id("CVE-2018-14679", "CVE-2018-14680", "CVE-2018-14681", "CVE-2018-14682", "CVE-2018-18584", "CVE-2018-18585", "CVE-2018-18586");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-02-01T09:43:59+0000");
  script_tag(name:"last_modification", value:"2022-02-01 09:43:59 +0000 (Tue, 01 Feb 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-04-26 11:45:00 +0000 (Mon, 26 Apr 2021)");

  script_name("Mageia: Security Advisory (MGASA-2018-0455)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2018-0455");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2018-0455.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=23365");
  script_xref(name:"URL", value:"https://usn.ubuntu.com/3728-1/");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2018/10/22/1");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2018/10/23/11");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cabextract, libmspack' package(s) announced via the MGASA-2018-0455 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Hanno Bock discovered that libmspack incorrectly handled certain CHM
files. An attacker could possibly use this issue to cause a denial of
service (CVE-2018-14679, CVE-2018-14680).

Jakub Wilk discovered that libmspack incorrectly handled certain KWAJ
files. An attacker could possibly use this issue to execute arbitrary
code (CVE-2018-14681).

Dmitry Glavatskikh discovered that libmspack incorrectly certain CHM
files. An attacker could possibly use this issue to execute arbitrary
code (CVE-2018-14682).

If a CAB file has a Quantum-compressed datablock with exactly 38912
compressed bytes, cabextract would write exactly one byte beyond its
input buffer (CVE-2018-18584).

libmspack didn't reject blank CHM filenames that are blank because they
have embedded null bytes, not just because they are zero-length
(CVE-2018-18585).

chmextract didn't protect from absolute/relative pathnames in CHM files
(CVE-2018-18586).");

  script_tag(name:"affected", value:"'cabextract, libmspack' package(s) on Mageia 6.");

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

if(release == "MAGEIA6") {

  if(!isnull(res = isrpmvuln(pkg:"cabextract", rpm:"cabextract~1.9~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64mspack-devel", rpm:"lib64mspack-devel~0.9.1~0.alpha.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64mspack0", rpm:"lib64mspack0~0.9.1~0.alpha.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmspack", rpm:"libmspack~0.9.1~0.alpha.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmspack-devel", rpm:"libmspack-devel~0.9.1~0.alpha.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmspack0", rpm:"libmspack0~0.9.1~0.alpha.1.mga6", rls:"MAGEIA6"))) {
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
