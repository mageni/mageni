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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.1418.1");
  script_cve_id("CVE-2021-36373", "CVE-2021-36374");
  script_tag(name:"creation_date", value:"2022-04-27 12:01:00 +0000 (Wed, 27 Apr 2022)");
  script_version("2022-04-27T12:01:00+0000");
  script_tag(name:"last_modification", value:"2022-04-27 12:01:00 +0000 (Wed, 27 Apr 2022)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-16 19:13:00 +0000 (Fri, 16 Jul 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:1418-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3|SLES15\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:1418-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20221418-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ant' package(s) announced via the SUSE-SU-2022:1418-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for ant fixes the following issues:

CVE-2021-36373: Fixed an excessive memory allocation when reading a
 specially crafted TAR archive (bsc#1188468).

CVE-2021-36374: Fixed an excessive memory allocation when reading a
 specially crafted ZIP archive (bsc#1188469).");

  script_tag(name:"affected", value:"'ant' package(s) on SUSE Linux Enterprise Module for Development Tools 15-SP3, SUSE Linux Enterprise Module for Development Tools 15-SP4, SUSE Linux Enterprise Realtime Extension 15-SP2.");

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

if(release == "SLES15.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"ant", rpm:"ant~1.10.7~150200.4.6.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ant-antlr", rpm:"ant-antlr~1.10.7~150200.4.6.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ant-apache-bcel", rpm:"ant-apache-bcel~1.10.7~150200.4.6.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ant-apache-bsf", rpm:"ant-apache-bsf~1.10.7~150200.4.6.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ant-apache-log4j", rpm:"ant-apache-log4j~1.10.7~150200.4.6.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ant-apache-oro", rpm:"ant-apache-oro~1.10.7~150200.4.6.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ant-apache-regexp", rpm:"ant-apache-regexp~1.10.7~150200.4.6.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ant-apache-resolver", rpm:"ant-apache-resolver~1.10.7~150200.4.6.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ant-commons-logging", rpm:"ant-commons-logging~1.10.7~150200.4.6.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ant-javamail", rpm:"ant-javamail~1.10.7~150200.4.6.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ant-jdepend", rpm:"ant-jdepend~1.10.7~150200.4.6.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ant-jmf", rpm:"ant-jmf~1.10.7~150200.4.6.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ant-junit", rpm:"ant-junit~1.10.7~150200.4.6.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ant-manual", rpm:"ant-manual~1.10.7~150200.4.6.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ant-scripts", rpm:"ant-scripts~1.10.7~150200.4.6.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ant-swing", rpm:"ant-swing~1.10.7~150200.4.6.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"ant", rpm:"ant~1.10.7~150200.4.6.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ant-antlr", rpm:"ant-antlr~1.10.7~150200.4.6.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ant-apache-bcel", rpm:"ant-apache-bcel~1.10.7~150200.4.6.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ant-apache-bsf", rpm:"ant-apache-bsf~1.10.7~150200.4.6.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ant-apache-log4j", rpm:"ant-apache-log4j~1.10.7~150200.4.6.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ant-apache-oro", rpm:"ant-apache-oro~1.10.7~150200.4.6.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ant-apache-regexp", rpm:"ant-apache-regexp~1.10.7~150200.4.6.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ant-apache-resolver", rpm:"ant-apache-resolver~1.10.7~150200.4.6.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ant-commons-logging", rpm:"ant-commons-logging~1.10.7~150200.4.6.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ant-javamail", rpm:"ant-javamail~1.10.7~150200.4.6.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ant-jdepend", rpm:"ant-jdepend~1.10.7~150200.4.6.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ant-jmf", rpm:"ant-jmf~1.10.7~150200.4.6.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ant-junit", rpm:"ant-junit~1.10.7~150200.4.6.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ant-manual", rpm:"ant-manual~1.10.7~150200.4.6.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ant-scripts", rpm:"ant-scripts~1.10.7~150200.4.6.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ant-swing", rpm:"ant-swing~1.10.7~150200.4.6.1", rls:"SLES15.0SP4"))) {
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
