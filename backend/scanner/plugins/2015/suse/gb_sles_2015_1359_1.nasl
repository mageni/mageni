# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2015.1359.1");
  script_cve_id("CVE-2015-0295","CVE-2015-1858","CVE-2015-1859");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2021-04-19T13:49:56+0000");
  script_tag(name:"last_modification", value:"2021-04-20 10:28:26 +0000 (Tue, 20 Apr 2021)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("SUSE Linux Enterprise Server: Security Advisory (SUSE-SU-2015:1359-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0)");

  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2015-August/001528.html");

  script_tag(name:"summary", value:"The remote host is missing an update for 'libqt4'
  package(s) announced via the SUSE-SU-2015:1359-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Please see the references for more information on the vulnerabilities.");

  script_tag(name:"affected", value:"'libqt4' package(s) on SUSE Linux Enterprise Server 12 (ppc64le s390x x86_64), SUSE Linux Enterprise Server 12 (s390x x86_64)");

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

if(release == "SLES12.0") {
  if(!isnull(res = isrpmvuln(pkg:"libqt4", rpm:"libqt4~4.8.6~4.2", rls:"SLES12.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4-debuginfo", rpm:"libqt4-debuginfo~4.8.6~4.2", rls:"SLES12.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4-debugsource", rpm:"libqt4-debugsource~4.8.6~4.2", rls:"SLES12.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4-devel-doc-debuginfo", rpm:"libqt4-devel-doc-debuginfo~4.8.6~4.6", rls:"SLES12.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4-devel-doc-debugsource", rpm:"libqt4-devel-doc-debugsource~4.8.6~4.6", rls:"SLES12.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4-qt3support", rpm:"libqt4-qt3support~4.8.6~4.2", rls:"SLES12.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4-qt3support-debuginfo", rpm:"libqt4-qt3support-debuginfo~4.8.6~4.2", rls:"SLES12.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4-sql", rpm:"libqt4-sql~4.8.6~4.2", rls:"SLES12.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4-sql-debuginfo", rpm:"libqt4-sql-debuginfo~4.8.6~4.2", rls:"SLES12.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4-sql-mysql", rpm:"libqt4-sql-mysql~4.8.6~4.1", rls:"SLES12.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4-sql-sqlite", rpm:"libqt4-sql-sqlite~4.8.6~4.2", rls:"SLES12.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4-sql-sqlite-debuginfo", rpm:"libqt4-sql-sqlite-debuginfo~4.8.6~4.2", rls:"SLES12.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4-x11", rpm:"libqt4-x11~4.8.6~4.2", rls:"SLES12.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4-x11-debuginfo", rpm:"libqt4-x11-debuginfo~4.8.6~4.2", rls:"SLES12.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt4-x11-tools", rpm:"qt4-x11-tools~4.8.6~4.6", rls:"SLES12.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt4-x11-tools-debuginfo", rpm:"qt4-x11-tools-debuginfo~4.8.6~4.6", rls:"SLES12.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4-32bit", rpm:"libqt4-32bit~4.8.6~4.2", rls:"SLES12.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4-debuginfo-32bit", rpm:"libqt4-debuginfo-32bit~4.8.6~4.2", rls:"SLES12.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4-qt3support-32bit", rpm:"libqt4-qt3support-32bit~4.8.6~4.2", rls:"SLES12.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4-qt3support-debuginfo-32bit", rpm:"libqt4-qt3support-debuginfo-32bit~4.8.6~4.2", rls:"SLES12.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4-sql-32bit", rpm:"libqt4-sql-32bit~4.8.6~4.2", rls:"SLES12.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4-sql-debuginfo-32bit", rpm:"libqt4-sql-debuginfo-32bit~4.8.6~4.2", rls:"SLES12.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4-x11-32bit", rpm:"libqt4-x11-32bit~4.8.6~4.2", rls:"SLES12.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4-x11-debuginfo-32bit", rpm:"libqt4-x11-debuginfo-32bit~4.8.6~4.2", rls:"SLES12.0"))){
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
