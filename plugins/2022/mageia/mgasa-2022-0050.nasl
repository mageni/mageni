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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0050");
  script_cve_id("CVE-2021-30613", "CVE-2021-30616", "CVE-2021-30618", "CVE-2021-30625", "CVE-2021-30626", "CVE-2021-30627", "CVE-2021-30628", "CVE-2021-30629", "CVE-2021-30630", "CVE-2021-30633", "CVE-2021-3517", "CVE-2021-3541", "CVE-2021-37962", "CVE-2021-37967", "CVE-2021-37968", "CVE-2021-37971", "CVE-2021-37972", "CVE-2021-37973", "CVE-2021-37975", "CVE-2021-37978", "CVE-2021-37979", "CVE-2021-37980", "CVE-2021-37984", "CVE-2021-37987", "CVE-2021-37989", "CVE-2021-37992", "CVE-2021-37993", "CVE-2021-37996", "CVE-2021-38001", "CVE-2021-38003", "CVE-2021-38005", "CVE-2021-38007", "CVE-2021-38009", "CVE-2021-38010", "CVE-2021-38012", "CVE-2021-38015", "CVE-2021-38017", "CVE-2021-38018", "CVE-2021-38019", "CVE-2021-38021", "CVE-2021-38022", "CVE-2021-4057", "CVE-2021-4058", "CVE-2021-4059", "CVE-2021-4062", "CVE-2021-4078", "CVE-2021-4079", "CVE-2021-4098", "CVE-2021-4099", "CVE-2021-4101", "CVE-2021-4102");
  script_tag(name:"creation_date", value:"2022-02-09 07:40:33 +0000 (Wed, 09 Feb 2022)");
  script_version("2022-02-09T07:40:33+0000");
  script_tag(name:"last_modification", value:"2022-02-09 07:40:33 +0000 (Wed, 09 Feb 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-10-12 22:43:00 +0000 (Tue, 12 Oct 2021)");

  script_name("Mageia: Security Advisory (MGASA-2022-0050)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0050");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0050.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=29973");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/2MLX3OHXV7SCLP5MK4AA5TVXPPNSWDUP/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qtwebengine5' package(s) announced via the MGASA-2022-0050 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The qtwebengine5 package has been updated to version 5.15.8, fixing several
security issues in the bundled chromium code. See the referenced package
announcement for details.");

  script_tag(name:"affected", value:"'qtwebengine5' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5pdf5", rpm:"lib64qt5pdf5~5.15.8~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5pdfwidgets5", rpm:"lib64qt5pdfwidgets5~5.15.8~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5webengine-devel", rpm:"lib64qt5webengine-devel~5.15.8~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5webengine5", rpm:"lib64qt5webengine5~5.15.8~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5webenginecore5", rpm:"lib64qt5webenginecore5~5.15.8~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5webenginewidgets5", rpm:"lib64qt5webenginewidgets5~5.15.8~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5pdf5", rpm:"libqt5pdf5~5.15.8~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5pdfwidgets5", rpm:"libqt5pdfwidgets5~5.15.8~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5webengine-devel", rpm:"libqt5webengine-devel~5.15.8~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5webengine5", rpm:"libqt5webengine5~5.15.8~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5webenginecore5", rpm:"libqt5webenginecore5~5.15.8~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5webenginewidgets5", rpm:"libqt5webenginewidgets5~5.15.8~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qtwebengine5", rpm:"qtwebengine5~5.15.8~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qtwebengine5-doc", rpm:"qtwebengine5-doc~5.15.8~1.mga8", rls:"MAGEIA8"))) {
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
