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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.2893.1");
  script_cve_id("CVE-2021-23214", "CVE-2021-23222", "CVE-2022-1552", "CVE-2022-2625");
  script_tag(name:"creation_date", value:"2022-08-26 04:54:58 +0000 (Fri, 26 Aug 2022)");
  script_version("2022-08-26T04:54:58+0000");
  script_tag(name:"last_modification", value:"2022-08-26 04:54:58 +0000 (Fri, 26 Aug 2022)");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-15 15:49:00 +0000 (Tue, 15 Mar 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:2893-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0|SLES15\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:2893-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20222893-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'postgresql10' package(s) announced via the SUSE-SU-2022:2893-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for postgresql10 fixes the following issues:

Upgrade to 10.22:

CVE-2022-2625: Fixed an issue where extension scripts would replace
 objects not belonging to that extension (bsc#1202368).

Upgrade to 10.21:

CVE-2022-1552: Confined additional operations within 'security
 restricted operation' sandboxes (bsc#1199475).

Upgrade to 10.20 (bsc#1195680)

Add constraints file with 12GB of memory for s390x as a workaround
 (boo#1190740)

Upgrade to version 10.19 (bsc#1192516):

CVE-2021-23214: Made the server reject extraneous data after an SSL or
 GSS encryption handshake

CVE-2021-23222: Made libpq reject extraneous data after an SSL or GSS
 encryption handshake

Fix for build with llvm12 on s390x. (bsc#1185952)

Re-enable 'icu' for PostgreSQL 10. (bsc#1179945)

Add postgresqlXX-server-devel as a dependency for
 postgresql13-server-devel. (bsc#1187751)

Upgrade to version 10.18. (bsc#1190177)");

  script_tag(name:"affected", value:"'postgresql10' package(s) on SUSE CaaS Platform 4.0, SUSE Enterprise Storage 6, SUSE Linux Enterprise High Performance Computing 15, SUSE Linux Enterprise High Performance Computing 15-SP1, SUSE Linux Enterprise Server 15, SUSE Linux Enterprise Server 15-SP1, SUSE Linux Enterprise Server for SAP 15, SUSE Linux Enterprise Server for SAP 15-SP1.");

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

if(release == "SLES15.0") {

  if(!isnull(res = isrpmvuln(pkg:"libecpg6", rpm:"libecpg6~10.22~150000.4.42.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libecpg6-debuginfo", rpm:"libecpg6-debuginfo~10.22~150000.4.42.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpq5", rpm:"libpq5~10.22~150000.4.42.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpq5-debuginfo", rpm:"libpq5-debuginfo~10.22~150000.4.42.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql", rpm:"postgresql~12.0.1~150000.8.19.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql-contrib", rpm:"postgresql-contrib~12.0.1~150000.8.19.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql-devel", rpm:"postgresql-devel~12.0.1~150000.8.19.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql-docs", rpm:"postgresql-docs~12.0.1~150000.8.19.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql-plperl", rpm:"postgresql-plperl~12.0.1~150000.8.19.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql-plpython", rpm:"postgresql-plpython~12.0.1~150000.8.19.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql-pltcl", rpm:"postgresql-pltcl~12.0.1~150000.8.19.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql-server", rpm:"postgresql-server~12.0.1~150000.8.19.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql-server-devel", rpm:"postgresql-server-devel~12.0.1~150000.8.19.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql10", rpm:"postgresql10~10.22~150000.4.42.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql10-contrib", rpm:"postgresql10-contrib~10.22~150000.4.42.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql10-contrib-debuginfo", rpm:"postgresql10-contrib-debuginfo~10.22~150000.4.42.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql10-debuginfo", rpm:"postgresql10-debuginfo~10.22~150000.4.42.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql10-debugsource", rpm:"postgresql10-debugsource~10.22~150000.4.42.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql10-devel", rpm:"postgresql10-devel~10.22~150000.4.42.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql10-devel-debuginfo", rpm:"postgresql10-devel-debuginfo~10.22~150000.4.42.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql10-docs", rpm:"postgresql10-docs~10.22~150000.4.42.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql10-plperl", rpm:"postgresql10-plperl~10.22~150000.4.42.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql10-plperl-debuginfo", rpm:"postgresql10-plperl-debuginfo~10.22~150000.4.42.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql10-plpython", rpm:"postgresql10-plpython~10.22~150000.4.42.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql10-plpython-debuginfo", rpm:"postgresql10-plpython-debuginfo~10.22~150000.4.42.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql10-pltcl", rpm:"postgresql10-pltcl~10.22~150000.4.42.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql10-pltcl-debuginfo", rpm:"postgresql10-pltcl-debuginfo~10.22~150000.4.42.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql10-server", rpm:"postgresql10-server~10.22~150000.4.42.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql10-server-debuginfo", rpm:"postgresql10-server-debuginfo~10.22~150000.4.42.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"postgresql", rpm:"postgresql~12.0.1~150000.8.19.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql-contrib", rpm:"postgresql-contrib~12.0.1~150000.8.19.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql-devel", rpm:"postgresql-devel~12.0.1~150000.8.19.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql-docs", rpm:"postgresql-docs~12.0.1~150000.8.19.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql-plperl", rpm:"postgresql-plperl~12.0.1~150000.8.19.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql-plpython", rpm:"postgresql-plpython~12.0.1~150000.8.19.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql-pltcl", rpm:"postgresql-pltcl~12.0.1~150000.8.19.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql-server", rpm:"postgresql-server~12.0.1~150000.8.19.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql-server-devel", rpm:"postgresql-server-devel~12.0.1~150000.8.19.1", rls:"SLES15.0SP1"))) {
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
