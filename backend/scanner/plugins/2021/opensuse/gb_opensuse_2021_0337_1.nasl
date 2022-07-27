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
  script_oid("1.3.6.1.4.1.25623.1.0.853757");
  script_version("2021-04-21T07:29:02+0000");
  script_cve_id("CVE-2020-25694", "CVE-2020-25695", "CVE-2020-25696");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2021-04-21 10:10:24 +0000 (Wed, 21 Apr 2021)");
  script_tag(name:"creation_date", value:"2021-04-16 05:02:59 +0000 (Fri, 16 Apr 2021)");
  script_name("openSUSE: Security Advisory for postgresql, (openSUSE-SU-2021:0337-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.2");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:0337-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/IQQBNVIVAXDZCJPFZE43ZEZ3C6DSC3WG");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'postgresql, '
  package(s) announced via the openSUSE-SU-2021:0337-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for postgresql, postgresql13 fixes the following issues:

     This update ships postgresql13.

     Upgrade to version 13.1:

  * CVE-2020-25695, bsc#1178666: Block DECLARE CURSOR ... WITH HOLD and
       firing of deferred triggers within index expressions and materialized
       view queries.

  * CVE-2020-25694, bsc#1178667: a) Fix usage of complex connection-string
       parameters in pg_dump, pg_restore, clusterdb, reindexdb, and vacuumdb.
       b) When psql&#x27 s \connect command re-uses connection parameters, ensure
       that all non-overridden parameters from a previous connection string are
       re-used.

  * CVE-2020-25696, bsc#1178668: Prevent psql&#x27 s \gset command from modifying
       specially-treated variables.

  * Fix recently-added timetz test case so it works when the USA is not
       observing daylight savings time. (obsoletes postgresql-timetz.patch)

     Initial packaging of PostgreSQL 13:

  - bsc#1178961: %ghost the symlinks to pg_config and ecpg.

     Changes in postgresql wrapper package:

  - Bump major version to 13.

  - We also transfer PostgreSQL 9.4.26 to the new package layout in
       SLE12-SP2 and newer. Reflect this in the conflict with postgresql94.

  - Also conflict with PostgreSQL versions before 9.

  - Conflicting with older versions is not limited to SLE.

     This update was imported from the SUSE:SLE-15-SP2:Update update project.");

  script_tag(name:"affected", value:"'postgresql, ' package(s) on openSUSE Leap 15.2.");

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

if(release == "openSUSELeap15.2") {

  if(!isnull(res = isrpmvuln(pkg:"postgresql", rpm:"postgresql~13~lp152.3.6.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql-contrib", rpm:"postgresql-contrib~13~lp152.3.6.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql-devel", rpm:"postgresql-devel~13~lp152.3.6.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql-docs", rpm:"postgresql-docs~13~lp152.3.6.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql-llvmjit", rpm:"postgresql-llvmjit~13~lp152.3.6.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql-plperl", rpm:"postgresql-plperl~13~lp152.3.6.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql-plpython", rpm:"postgresql-plpython~13~lp152.3.6.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql-pltcl", rpm:"postgresql-pltcl~13~lp152.3.6.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql-server", rpm:"postgresql-server~13~lp152.3.6.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql-server-devel", rpm:"postgresql-server-devel~13~lp152.3.6.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql-test", rpm:"postgresql-test~13~lp152.3.6.1", rls:"openSUSELeap15.2"))) {
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
