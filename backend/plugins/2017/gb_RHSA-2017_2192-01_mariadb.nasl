###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_RHSA-2017_2192-01_mariadb.nasl 12497 2018-11-23 08:28:21Z cfischer $
#
# RedHat Update for mariadb RHSA-2017:2192-01
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.871856");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2017-08-04 12:46:28 +0530 (Fri, 04 Aug 2017)");
  script_cve_id("CVE-2016-5483", "CVE-2016-5617", "CVE-2016-6664", "CVE-2017-3238",
                "CVE-2017-3243", "CVE-2017-3244", "CVE-2017-3258", "CVE-2017-3265",
                "CVE-2017-3291", "CVE-2017-3302", "CVE-2017-3308", "CVE-2017-3309",
                "CVE-2017-3312", "CVE-2017-3313", "CVE-2017-3317", "CVE-2017-3318",
                "CVE-2017-3453", "CVE-2017-3456", "CVE-2017-3464", "CVE-2017-3600");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for mariadb RHSA-2017:2192-01");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'mariadb'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"MariaDB is a multi-user, multi-threaded SQL
  database server that is binary compatible with MySQL. The following packages
  have been upgraded to a later upstream version: mariadb (5.5.56). (BZ#1458933)
  Security Fix(es): * It was discovered that the mysql and mysqldump tools did not
  correctly handle database and table names containing newline characters. A
  database user with privileges to create databases or tables could cause the
  mysql command to execute arbitrary shell or SQL commands while restoring
  database backup created using the mysqldump tool. (CVE-2016-5483, CVE-2017-3600)

  * A flaw was found in the way the mysqld_safe script handled creation of error
  log file. The mysql operating system user could use this flaw to escalate their
  privileges to root. (CVE-2016-5617, CVE-2016-6664) * Multiple flaws were found
  in the way the MySQL init script handled initialization of the database data
  directory and permission setting on the error log file. The mysql operating
  system user could use these flaws to escalate their privileges to root.
  (CVE-2017-3265) * It was discovered that the mysqld_safe script honored the
  ledir option value set in a MySQL configuration file. A user able to modify one
  of the MySQL configuration files could use this flaw to escalate their
  privileges to root. (CVE-2017-3291) * Multiple flaws were found in the way the
  mysqld_safe script handled creation of error log file. The mysql operating
  system user could use these flaws to escalate their privileges to root.
  (CVE-2017-3312) * A flaw was found in the way MySQL client library
  (libmysqlclient) handled prepared statements when server connection was lost. A
  malicious server or a man-in-the-middle attacker could possibly use this flaw to
  crash an application using libmysqlclient. (CVE-2017-3302) * This update fixes
  several vulnerabilities in the MariaDB database server. Information about these
  flaws can be found on the Oracle Critical Patch Update Advisory page, listed in
  the References section. (CVE-2017-3238, CVE-2017-3243, CVE-2017-3244,
  CVE-2017-3258, CVE-2017-3308, CVE-2017-3309, CVE-2017-3313, CVE-2017-3317,
  CVE-2017-3318, CVE-2017-3453, CVE-2017-3456, CVE-2017-3464) Additional Changes:
  For detailed information on changes in this release, see the Red Hat Enterprise
  Linux 7.4 Release Notes linked from the References section.");
  script_tag(name:"affected", value:"mariadb on Red Hat Enterprise Linux Server (v. 7)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2017-August/msg00015.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_7");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_7")
{

  if ((res = isrpmvuln(pkg:"mariadb", rpm:"mariadb~5.5.56~2.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mariadb-bench", rpm:"mariadb-bench~5.5.56~2.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mariadb-debuginfo", rpm:"mariadb-debuginfo~5.5.56~2.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mariadb-devel", rpm:"mariadb-devel~5.5.56~2.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mariadb-libs", rpm:"mariadb-libs~5.5.56~2.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mariadb-server", rpm:"mariadb-server~5.5.56~2.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mariadb-test", rpm:"mariadb-test~5.5.56~2.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
