###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2016_2769_1.nasl 12381 2018-11-16 11:16:30Z cfischer $
#
# SuSE Update for mysql-community-server openSUSE-SU-2016:2769-1 (mysql-community-server)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.851430");
  script_version("$Revision: 12381 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-11-11 05:46:58 +0100 (Fri, 11 Nov 2016)");
  script_cve_id("CVE-2016-2105", "CVE-2016-3459", "CVE-2016-3477", "CVE-2016-3486",
                "CVE-2016-3492", "CVE-2016-3501", "CVE-2016-3521", "CVE-2016-3614",
                "CVE-2016-3615", "CVE-2016-5439", "CVE-2016-5440", "CVE-2016-5507",
                "CVE-2016-5584", "CVE-2016-5609", "CVE-2016-5612", "CVE-2016-5616",
                "CVE-2016-5617", "CVE-2016-5626", "CVE-2016-5627", "CVE-2016-5629",
                "CVE-2016-5630", "CVE-2016-6304", "CVE-2016-6662", "CVE-2016-7440",
                "CVE-2016-8283", "CVE-2016-8284", "CVE-2016-8288");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for mysql-community-server openSUSE-SU-2016:2769-1 (mysql-community-server)");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"mysql-community-server was updated to 5.6.34 to fix the following issues:

  * fixed CVEs: CVE-2016-6304, CVE-2016-6662, CVE-2016-7440, CVE-2016-5584,
  CVE-2016-5617, CVE-2016-5616, CVE-2016-5626, CVE-2016-3492,
  CVE-2016-5629, CVE-2016-5507, CVE-2016-8283, CVE-2016-5609,
  CVE-2016-5612, CVE-2016-5627, CVE-2016-5630, CVE-2016-8284,
  CVE-2016-8288, CVE-2016-3477, CVE-2016-2105, CVE-2016-3486,
  CVE-2016-3501, CVE-2016-3521, CVE-2016-3615, CVE-2016-3614,
  CVE-2016-3459, CVE-2016-5439, CVE-2016-5440

  * fixes SUSE Bugs: [boo#999666], [boo#998309], [boo#1005581],
  [boo#1005558], [boo#1005563], [boo#1005562], [boo#1005566],
  [boo#1005555], [boo#1005569], [boo#1005557], [boo#1005582],
  [boo#1005560], [boo#1005561], [boo#1005567], [boo#1005570],
  [boo#1005583], [boo#1005586], [boo#989913], [boo#977614],
  [boo#989914], [boo#989915], [boo#989919], [boo#989922], [boo#989921],
  [boo#989911], [boo#989925], [boo#989926]

  - append '--ignore-db-dir=lost+found' to the mysqld options in
  'mysql-systemd-helper' script if 'lost+found' directory is found in
  $datadir [boo#986251]

  - remove syslog.target from *.service files [boo#983938]

  - add systemd to deps to build on leap and friends

  - replace '%{_libexecdir}/systemd/system' with %{_unitdir} macro

  - remove useless mysql@default.service [boo#971456]

  - replace all occurrences of the string '@sysconfdir@' with '/etc' in
  mysql-community-server-5.6.3-logrotate.patch as it wasn't expanded
  properly [boo#990890]

  - remove '%define _rundir' as 13.1 is out of support scope

  - run 'usermod -g mysql mysql' only if mysql user is not in mysql group.
  Run 'usermod -s /bin/false/ mysql' only if mysql user doesn't have
  '/bin/false' shell set.

  - re-enable mysql profiling");
  script_tag(name:"affected", value:"mysql-community-server on openSUSE Leap 42.1, openSUSE 13.2");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'mysql-community-server'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSE13\.2");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);
res = "";

if(release == "openSUSE13.2")
{

  if ((res = isrpmvuln(pkg:"libmysql56client18", rpm:"libmysql56client18~5.6.34~2.23.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libmysql56client18-debuginfo", rpm:"libmysql56client18-debuginfo~5.6.34~2.23.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libmysql56client_r18", rpm:"libmysql56client_r18~5.6.34~2.23.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mysql-community-server", rpm:"mysql-community-server~5.6.34~2.23.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mysql-community-server-bench", rpm:"mysql-community-server-bench~5.6.34~2.23.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mysql-community-server-bench-debuginfo", rpm:"mysql-community-server-bench-debuginfo~5.6.34~2.23.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mysql-community-server-client", rpm:"mysql-community-server-client~5.6.34~2.23.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mysql-community-server-client-debuginfo", rpm:"mysql-community-server-client-debuginfo~5.6.34~2.23.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mysql-community-server-debuginfo", rpm:"mysql-community-server-debuginfo~5.6.34~2.23.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mysql-community-server-debugsource", rpm:"mysql-community-server-debugsource~5.6.34~2.23.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mysql-community-server-errormessages", rpm:"mysql-community-server-errormessages~5.6.34~2.23.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mysql-community-server-test", rpm:"mysql-community-server-test~5.6.34~2.23.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mysql-community-server-test-debuginfo", rpm:"mysql-community-server-test-debuginfo~5.6.34~2.23.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mysql-community-server-tools", rpm:"mysql-community-server-tools~5.6.34~2.23.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mysql-community-server-tools-debuginfo", rpm:"mysql-community-server-tools-debuginfo~5.6.34~2.23.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libmysql56client18-32bit", rpm:"libmysql56client18-32bit~5.6.34~2.23.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libmysql56client18-debuginfo-32bit", rpm:"libmysql56client18-debuginfo-32bit~5.6.34~2.23.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libmysql56client_r18-32bit", rpm:"libmysql56client_r18-32bit~5.6.34~2.23.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
