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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2014.0263");
  script_cve_id("CVE-2013-4549", "CVE-2014-0190");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-31T07:41:30+0000");
  script_tag(name:"last_modification", value:"2022-01-31 07:41:30 +0000 (Mon, 31 Jan 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-16 12:44:00 +0000 (Wed, 16 Jun 2021)");

  script_name("Mageia: Security Advisory (MGASA-2014-0263)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(3|4)");

  script_xref(name:"Advisory-ID", value:"MGASA-2014-0263");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2014-0263.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=13509");
  script_xref(name:"URL", value:"http://lists.qt-project.org/pipermail/announce/2013-December/000036.html");
  script_xref(name:"URL", value:"http://lists.qt-project.org/pipermail/announce/2014-April/000045.html");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/pipermail/package-announce/2014-January/127076.html");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/pipermail/package-announce/2014-June/134040.html");
  script_xref(name:"URL", value:"http://advisories.mageia.org/MGASA-2014-0009.html");
  script_xref(name:"URL", value:"http://advisories.mageia.org/MGASA-2014-0240.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qt3, qt3' package(s) announced via the MGASA-2014-0263 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated qt3 packages fix security vulnerabilities:

QXmlSimpleReader in Qt versions prior to 5.2 supports expansion of
internal entities in XML documents without placing restrictions to
ensure the document does not cause excessive memory usage. If an
application using this API processes untrusted data then the
application may use unexpected amounts of memory if a malicious
document is processed (CVE-2013-4549).

A NULL pointer dereference flaw was found in QGIFFormat::fillRect in
QtGui. If an application using the qt-x11 libraries opened a malicious
GIF file with invalid width and height values, it could cause the
application to crash (CVE-2014-0190).");

  script_tag(name:"affected", value:"'qt3, qt3' package(s) on Mageia 3, Mageia 4.");

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

if(release == "MAGEIA3") {

  if(!isnull(res = isrpmvuln(pkg:"lib64qt3", rpm:"lib64qt3~3.3.8b~32.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt3-mysql", rpm:"lib64qt3-mysql~3.3.8b~32.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt3-odbc", rpm:"lib64qt3-odbc~3.3.8b~32.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt3-psql", rpm:"lib64qt3-psql~3.3.8b~32.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt3-sqlite", rpm:"lib64qt3-sqlite~3.3.8b~32.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt3", rpm:"libqt3~3.3.8b~32.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt3-mysql", rpm:"libqt3-mysql~3.3.8b~32.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt3-odbc", rpm:"libqt3-odbc~3.3.8b~32.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt3-psql", rpm:"libqt3-psql~3.3.8b~32.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt3-sqlite", rpm:"libqt3-sqlite~3.3.8b~32.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt3", rpm:"qt3~3.3.8b~32.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt3-common", rpm:"qt3-common~3.3.8b~32.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA4") {

  if(!isnull(res = isrpmvuln(pkg:"lib64qt3", rpm:"lib64qt3~3.3.8b~33.2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt3-mysql", rpm:"lib64qt3-mysql~3.3.8b~33.2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt3-odbc", rpm:"lib64qt3-odbc~3.3.8b~33.2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt3-psql", rpm:"lib64qt3-psql~3.3.8b~33.2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt3-sqlite", rpm:"lib64qt3-sqlite~3.3.8b~33.2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt3", rpm:"libqt3~3.3.8b~33.2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt3-mysql", rpm:"libqt3-mysql~3.3.8b~33.2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt3-odbc", rpm:"libqt3-odbc~3.3.8b~33.2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt3-psql", rpm:"libqt3-psql~3.3.8b~33.2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt3-sqlite", rpm:"libqt3-sqlite~3.3.8b~33.2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt3", rpm:"qt3~3.3.8b~33.2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt3-common", rpm:"qt3-common~3.3.8b~33.2.mga4", rls:"MAGEIA4"))) {
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
