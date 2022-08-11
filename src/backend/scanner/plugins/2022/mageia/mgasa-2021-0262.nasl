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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2021.0262");
  script_cve_id("CVE-2021-3481");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"Greenbone");
  script_tag(name:"severity_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");

  script_name("Mageia: Security Advisory (MGASA-2021-0262)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(7|8)");

  script_xref(name:"Advisory-ID", value:"MGASA-2021-0262");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2021-0262.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=29014");
  script_xref(name:"URL", value:"https://bugreports.qt.io/browse/QTBUG-91507");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/O57HZYEVZNCW5L74PDD7K44E7XZEBXRK/");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/GOBQ75US43TETW2OID6APHQRENDFK4BO/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qt4, qt4, qtsvg5, qtsvg5' package(s) announced via the MGASA-2021-0262 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An out of bounds read in function QRadialFetchSimd from crafted svg file may
lead to information disclosure or other potential consequences. This update
includes the backported upstream fix and should resolve the security issue
(CVE-2021-3481).");

  script_tag(name:"affected", value:"'qt4, qt4, qtsvg5, qtsvg5' package(s) on Mageia 7, Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64qt3support4", rpm:"lib64qt3support4~4.8.7~26.3.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt4-database-plugin-mysql", rpm:"lib64qt4-database-plugin-mysql~4.8.7~26.3.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt4-database-plugin-pgsql", rpm:"lib64qt4-database-plugin-pgsql~4.8.7~26.3.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt4-database-plugin-sqlite", rpm:"lib64qt4-database-plugin-sqlite~4.8.7~26.3.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt4-database-plugin-tds", rpm:"lib64qt4-database-plugin-tds~4.8.7~26.3.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt4-devel", rpm:"lib64qt4-devel~4.8.7~26.3.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5svg-devel", rpm:"lib64qt5svg-devel~5.12.6~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5svg5", rpm:"lib64qt5svg5~5.12.6~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qtclucene4", rpm:"lib64qtclucene4~4.8.7~26.3.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qtcore4", rpm:"lib64qtcore4~4.8.7~26.3.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qtdbus4", rpm:"lib64qtdbus4~4.8.7~26.3.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qtdeclarative4", rpm:"lib64qtdeclarative4~4.8.7~26.3.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qtdesigner4", rpm:"lib64qtdesigner4~4.8.7~26.3.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qtgui4", rpm:"lib64qtgui4~4.8.7~26.3.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qthelp4", rpm:"lib64qthelp4~4.8.7~26.3.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qtmultimedia4", rpm:"lib64qtmultimedia4~4.8.7~26.3.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qtnetwork4", rpm:"lib64qtnetwork4~4.8.7~26.3.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qtopengl4", rpm:"lib64qtopengl4~4.8.7~26.3.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qtscript4", rpm:"lib64qtscript4~4.8.7~26.3.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qtscripttools4", rpm:"lib64qtscripttools4~4.8.7~26.3.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qtsql4", rpm:"lib64qtsql4~4.8.7~26.3.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qtsvg4", rpm:"lib64qtsvg4~4.8.7~26.3.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qttest4", rpm:"lib64qttest4~4.8.7~26.3.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qtxml4", rpm:"lib64qtxml4~4.8.7~26.3.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qtxmlpatterns4", rpm:"lib64qtxmlpatterns4~4.8.7~26.3.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt3support4", rpm:"libqt3support4~4.8.7~26.3.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4-database-plugin-mysql", rpm:"libqt4-database-plugin-mysql~4.8.7~26.3.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4-database-plugin-pgsql", rpm:"libqt4-database-plugin-pgsql~4.8.7~26.3.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4-database-plugin-sqlite", rpm:"libqt4-database-plugin-sqlite~4.8.7~26.3.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4-database-plugin-tds", rpm:"libqt4-database-plugin-tds~4.8.7~26.3.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4-devel", rpm:"libqt4-devel~4.8.7~26.3.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5svg-devel", rpm:"libqt5svg-devel~5.12.6~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5svg5", rpm:"libqt5svg5~5.12.6~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqtclucene4", rpm:"libqtclucene4~4.8.7~26.3.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqtcore4", rpm:"libqtcore4~4.8.7~26.3.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqtdbus4", rpm:"libqtdbus4~4.8.7~26.3.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqtdeclarative4", rpm:"libqtdeclarative4~4.8.7~26.3.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqtdesigner4", rpm:"libqtdesigner4~4.8.7~26.3.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqtgui4", rpm:"libqtgui4~4.8.7~26.3.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqthelp4", rpm:"libqthelp4~4.8.7~26.3.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqtmultimedia4", rpm:"libqtmultimedia4~4.8.7~26.3.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqtnetwork4", rpm:"libqtnetwork4~4.8.7~26.3.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqtopengl4", rpm:"libqtopengl4~4.8.7~26.3.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqtscript4", rpm:"libqtscript4~4.8.7~26.3.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqtscripttools4", rpm:"libqtscripttools4~4.8.7~26.3.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqtsql4", rpm:"libqtsql4~4.8.7~26.3.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqtsvg4", rpm:"libqtsvg4~4.8.7~26.3.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqttest4", rpm:"libqttest4~4.8.7~26.3.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqtxml4", rpm:"libqtxml4~4.8.7~26.3.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqtxmlpatterns4", rpm:"libqtxmlpatterns4~4.8.7~26.3.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt4", rpm:"qt4~4.8.7~26.3.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt4-accessibility-plugin", rpm:"qt4-accessibility-plugin~4.8.7~26.3.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt4-assistant", rpm:"qt4-assistant~4.8.7~26.3.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt4-common", rpm:"qt4-common~4.8.7~26.3.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt4-demos", rpm:"qt4-demos~4.8.7~26.3.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt4-designer", rpm:"qt4-designer~4.8.7~26.3.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt4-designer-plugin-qt3support", rpm:"qt4-designer-plugin-qt3support~4.8.7~26.3.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt4-designer-plugin-webkit", rpm:"qt4-designer-plugin-webkit~4.8.7~26.3.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt4-devel-private", rpm:"qt4-devel-private~4.8.7~26.3.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt4-doc", rpm:"qt4-doc~4.8.7~26.3.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt4-examples", rpm:"qt4-examples~4.8.7~26.3.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt4-graphicssystems-plugin", rpm:"qt4-graphicssystems-plugin~4.8.7~26.3.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt4-linguist", rpm:"qt4-linguist~4.8.7~26.3.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt4-qdoc3", rpm:"qt4-qdoc3~4.8.7~26.3.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt4-qmlviewer", rpm:"qt4-qmlviewer~4.8.7~26.3.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt4-qtconfig", rpm:"qt4-qtconfig~4.8.7~26.3.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt4-qtdbus", rpm:"qt4-qtdbus~4.8.7~26.3.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt4-qvfb", rpm:"qt4-qvfb~4.8.7~26.3.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt4-xmlpatterns", rpm:"qt4-xmlpatterns~4.8.7~26.3.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qtsvg5", rpm:"qtsvg5~5.12.6~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qtsvg5-doc", rpm:"qtsvg5-doc~5.12.6~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA8") {

  if(!isnull(res = isrpmvuln(pkg:"lib64qt3support4", rpm:"lib64qt3support4~4.8.7~35.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt4-database-plugin-mysql", rpm:"lib64qt4-database-plugin-mysql~4.8.7~35.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt4-database-plugin-pgsql", rpm:"lib64qt4-database-plugin-pgsql~4.8.7~35.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt4-database-plugin-sqlite", rpm:"lib64qt4-database-plugin-sqlite~4.8.7~35.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt4-database-plugin-tds", rpm:"lib64qt4-database-plugin-tds~4.8.7~35.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt4-devel", rpm:"lib64qt4-devel~4.8.7~35.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5svg-devel", rpm:"lib64qt5svg-devel~5.15.2~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5svg5", rpm:"lib64qt5svg5~5.15.2~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qtclucene4", rpm:"lib64qtclucene4~4.8.7~35.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qtcore4", rpm:"lib64qtcore4~4.8.7~35.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qtdbus4", rpm:"lib64qtdbus4~4.8.7~35.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qtdeclarative4", rpm:"lib64qtdeclarative4~4.8.7~35.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qtdesigner4", rpm:"lib64qtdesigner4~4.8.7~35.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qtgui4", rpm:"lib64qtgui4~4.8.7~35.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qthelp4", rpm:"lib64qthelp4~4.8.7~35.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qtmultimedia4", rpm:"lib64qtmultimedia4~4.8.7~35.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qtnetwork4", rpm:"lib64qtnetwork4~4.8.7~35.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qtopengl4", rpm:"lib64qtopengl4~4.8.7~35.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qtscript4", rpm:"lib64qtscript4~4.8.7~35.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qtscripttools4", rpm:"lib64qtscripttools4~4.8.7~35.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qtsql4", rpm:"lib64qtsql4~4.8.7~35.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qtsvg4", rpm:"lib64qtsvg4~4.8.7~35.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qttest4", rpm:"lib64qttest4~4.8.7~35.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qtxml4", rpm:"lib64qtxml4~4.8.7~35.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qtxmlpatterns4", rpm:"lib64qtxmlpatterns4~4.8.7~35.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt3support4", rpm:"libqt3support4~4.8.7~35.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4-database-plugin-mysql", rpm:"libqt4-database-plugin-mysql~4.8.7~35.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4-database-plugin-pgsql", rpm:"libqt4-database-plugin-pgsql~4.8.7~35.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4-database-plugin-sqlite", rpm:"libqt4-database-plugin-sqlite~4.8.7~35.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4-database-plugin-tds", rpm:"libqt4-database-plugin-tds~4.8.7~35.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4-devel", rpm:"libqt4-devel~4.8.7~35.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5svg-devel", rpm:"libqt5svg-devel~5.15.2~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5svg5", rpm:"libqt5svg5~5.15.2~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqtclucene4", rpm:"libqtclucene4~4.8.7~35.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqtcore4", rpm:"libqtcore4~4.8.7~35.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqtdbus4", rpm:"libqtdbus4~4.8.7~35.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqtdeclarative4", rpm:"libqtdeclarative4~4.8.7~35.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqtdesigner4", rpm:"libqtdesigner4~4.8.7~35.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqtgui4", rpm:"libqtgui4~4.8.7~35.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqthelp4", rpm:"libqthelp4~4.8.7~35.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqtmultimedia4", rpm:"libqtmultimedia4~4.8.7~35.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqtnetwork4", rpm:"libqtnetwork4~4.8.7~35.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqtopengl4", rpm:"libqtopengl4~4.8.7~35.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqtscript4", rpm:"libqtscript4~4.8.7~35.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqtscripttools4", rpm:"libqtscripttools4~4.8.7~35.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqtsql4", rpm:"libqtsql4~4.8.7~35.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqtsvg4", rpm:"libqtsvg4~4.8.7~35.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqttest4", rpm:"libqttest4~4.8.7~35.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqtxml4", rpm:"libqtxml4~4.8.7~35.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqtxmlpatterns4", rpm:"libqtxmlpatterns4~4.8.7~35.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt4", rpm:"qt4~4.8.7~35.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt4-accessibility-plugin", rpm:"qt4-accessibility-plugin~4.8.7~35.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt4-assistant", rpm:"qt4-assistant~4.8.7~35.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt4-common", rpm:"qt4-common~4.8.7~35.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt4-demos", rpm:"qt4-demos~4.8.7~35.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt4-designer", rpm:"qt4-designer~4.8.7~35.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt4-designer-plugin-qt3support", rpm:"qt4-designer-plugin-qt3support~4.8.7~35.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt4-devel-private", rpm:"qt4-devel-private~4.8.7~35.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt4-doc", rpm:"qt4-doc~4.8.7~35.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt4-examples", rpm:"qt4-examples~4.8.7~35.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt4-graphicssystems-plugin", rpm:"qt4-graphicssystems-plugin~4.8.7~35.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt4-linguist", rpm:"qt4-linguist~4.8.7~35.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt4-qdoc3", rpm:"qt4-qdoc3~4.8.7~35.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt4-qmlviewer", rpm:"qt4-qmlviewer~4.8.7~35.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt4-qtconfig", rpm:"qt4-qtconfig~4.8.7~35.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt4-qtdbus", rpm:"qt4-qtdbus~4.8.7~35.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt4-qvfb", rpm:"qt4-qvfb~4.8.7~35.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt4-xmlpatterns", rpm:"qt4-xmlpatterns~4.8.7~35.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qtsvg5", rpm:"qtsvg5~5.15.2~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qtsvg5-doc", rpm:"qtsvg5-doc~5.15.2~1.1.mga8", rls:"MAGEIA8"))) {
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
