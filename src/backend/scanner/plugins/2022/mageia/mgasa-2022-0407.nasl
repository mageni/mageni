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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0407");
  script_cve_id("CVE-2020-21365");
  script_tag(name:"creation_date", value:"2022-11-07 04:28:34 +0000 (Mon, 07 Nov 2022)");
  script_version("2022-11-07T10:13:06+0000");
  script_tag(name:"last_modification", value:"2022-11-07 10:13:06 +0000 (Mon, 07 Nov 2022)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-16 17:37:00 +0000 (Tue, 16 Aug 2022)");

  script_name("Mageia: Security Advisory (MGASA-2022-0407)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0407");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0407.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=31023");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2022/dla-3158");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'wkhtmltopdf' package(s) announced via the MGASA-2022-0407 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Directory traversal vulnerability in wkhtmltopdf through 0.12.5 allows
remote attackers to read local files and disclose sensitive information
via a crafted html file running with the default configurations.
(CVE-2020-21365)");

  script_tag(name:"affected", value:"'wkhtmltopdf' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64wkhtmltox-devel", rpm:"lib64wkhtmltox-devel~0.12.5~4.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64wkhtmltox0", rpm:"lib64wkhtmltox0~0.12.5~4.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwkhtmltox-devel", rpm:"libwkhtmltox-devel~0.12.5~4.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwkhtmltox0", rpm:"libwkhtmltox0~0.12.5~4.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wkhtmltopdf", rpm:"wkhtmltopdf~0.12.5~4.1.mga8", rls:"MAGEIA8"))) {
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
