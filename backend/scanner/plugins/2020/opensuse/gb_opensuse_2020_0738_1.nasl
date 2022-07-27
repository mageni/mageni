# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.853187");
  script_version("2020-06-03T10:55:59+0000");
  script_cve_id("CVE-2020-13249");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-06-04 10:51:29 +0000 (Thu, 04 Jun 2020)");
  script_tag(name:"creation_date", value:"2020-05-30 03:00:36 +0000 (Sat, 30 May 2020)");
  script_name("openSUSE: Security Advisory for mariadb-connector-c (openSUSE-SU-2020:0738-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.1");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2020-05/msg00064.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mariadb-connector-c'
  package(s) announced via the openSUSE-SU-2020:0738-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for mariadb-connector-c fixes the following issues:

  Security issue fixed:

  - CVE-2020-13249: Fixed an improper validation of OK packets received from
  clients (bsc#1171550).

  Non-security issues fixed:

  - Update to release 3.1.8 (bsc#1171550)

  * CONC-304: Rename the static library to libmariadb.a and other
  libmariadb files in a consistent manner

  * CONC-441: Default user name for C/C is wrong if login user is
  different from effective user

  * CONC-449: Check $MARIADB_HOME/my.cnf in addition to $MYSQL_HOME/my.cnf

  * CONC-457: mysql_list_processes crashes in unpack_fields

  * CONC-458: mysql_get_timeout_value crashes when used improper

  * CONC-464: Fix static build for auth_gssapi_client plugin

  This update was imported from the SUSE:SLE-15:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2020-738=1");

  script_tag(name:"affected", value:"'mariadb-connector-c' package(s) on openSUSE Leap 15.1.");

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

if(release == "openSUSELeap15.1") {

  if(!isnull(res = isrpmvuln(pkg:"libmariadb-devel", rpm:"libmariadb-devel~3.1.8~lp151.3.12.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmariadb-devel-debuginfo", rpm:"libmariadb-devel-debuginfo~3.1.8~lp151.3.12.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmariadb3", rpm:"libmariadb3~3.1.8~lp151.3.12.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmariadb3-debuginfo", rpm:"libmariadb3-debuginfo~3.1.8~lp151.3.12.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmariadb_plugins", rpm:"libmariadb_plugins~3.1.8~lp151.3.12.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmariadb_plugins-debuginfo", rpm:"libmariadb_plugins-debuginfo~3.1.8~lp151.3.12.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmariadbprivate", rpm:"libmariadbprivate~3.1.8~lp151.3.12.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmariadbprivate-debuginfo", rpm:"libmariadbprivate-debuginfo~3.1.8~lp151.3.12.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-connector-c-debugsource", rpm:"mariadb-connector-c-debugsource~3.1.8~lp151.3.12.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmariadb3-32bit", rpm:"libmariadb3-32bit~3.1.8~lp151.3.12.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmariadb3-32bit-debuginfo", rpm:"libmariadb3-32bit-debuginfo~3.1.8~lp151.3.12.1", rls:"openSUSELeap15.1"))) {
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