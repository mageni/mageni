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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2020.0248");
  script_cve_id("CVE-2019-2228", "CVE-2019-8675", "CVE-2019-8696", "CVE-2019-8842", "CVE-2020-3898");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-29 16:02:00 +0000 (Thu, 29 Oct 2020)");

  script_name("Mageia: Security Advisory (MGASA-2020-0248)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2020-0248");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2020-0248.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=26531");
  script_xref(name:"URL", value:"https://usn.ubuntu.com/4105-1/");
  script_xref(name:"URL", value:"https://usn.ubuntu.com/4340-1/");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/CVE-2019-8842");
  script_xref(name:"URL", value:"https://github.com/apple/cups/releases/tag/v2.2.12");
  script_xref(name:"URL", value:"https://github.com/apple/cups/releases/tag/v2.2.13");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cups' package(s) announced via the MGASA-2020-0248 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated cups packages fix security vulnerabilities:

It was discovered that CUPS incorrectly handled certain language values.
A local attacker could possibly use this issue to cause CUPS to crash,
leading to a denial of service, or possibly obtain sensitive information
(CVE-2019-2228).

Stephan Zeisberg discovered that the CUPS SNMP backend incorrectly
handled encoded ASN.1 inputs. A remote attacker could possibly use this
issue to cause CUPS to crash by providing specially crafted network
traffic (CVE-2019-8675, CVE-2019-8696).

The ippReadIO function may under-read an extension (CVE-2019-8842).

Stephan Zeisberg discovered that CUPS incorrectly handled certain
malformed ppd files. A local attacker could possibly use this issue to
execute arbitrary code (CVE-2020-3898).

The cups package has been updated to version 2.2.13 and patched to fix
these issues and other bugs.

Also, this update will hopefully fix the cups service failing to start at
boot on some systems.");

  script_tag(name:"affected", value:"'cups' package(s) on Mageia 7.");

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

if(release == "MAGEIA7") {

  if(!isnull(res = isrpmvuln(pkg:"cups", rpm:"cups~2.2.13~1.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups-common", rpm:"cups-common~2.2.13~1.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups-filesystem", rpm:"cups-filesystem~2.2.13~1.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64cups2", rpm:"lib64cups2~2.2.13~1.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64cups2-devel", rpm:"lib64cups2-devel~2.2.13~1.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcups2", rpm:"libcups2~2.2.13~1.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcups2-devel", rpm:"libcups2-devel~2.2.13~1.2.mga7", rls:"MAGEIA7"))) {
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
