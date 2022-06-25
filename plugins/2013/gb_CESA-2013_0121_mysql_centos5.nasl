###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for mysql CESA-2013:0121 centos5
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2013-January/019160.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881559");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2013-01-21 09:38:02 +0530 (Mon, 21 Jan 2013)");
  script_cve_id("CVE-2012-4452", "CVE-2009-4030");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_name("CentOS Update for mysql CESA-2013:0121 centos5");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mysql'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  script_tag(name:"affected", value:"mysql on CentOS 5");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"MySQL is a multi-user, multi-threaded SQL database server. It consists of
  the MySQL server daemon (mysqld) and many client programs and libraries.

  It was found that the fix for the CVE-2009-4030 issue, a flaw in the way
  MySQL checked the paths used as arguments for the DATA DIRECTORY and INDEX
  DIRECTORY directives when the 'datadir' option was configured with a
  relative path, was incorrectly removed when the mysql packages in Red Hat
  Enterprise Linux 5 were updated to version 5.0.95 via RHSA-2012:0127. An
  authenticated attacker could use this flaw to bypass the restriction
  preventing the use of subdirectories of the MySQL data directory being used
  as DATA DIRECTORY and INDEX DIRECTORY paths. This update re-applies the fix
  for CVE-2009-4030. (CVE-2012-4452)

  Note: If the use of the DATA DIRECTORY and INDEX DIRECTORY directives were
  disabled as described in RHSA-2010:0109 (by adding 'symbolic-links=0' to
  the '[mysqld]' section of the 'my.cnf' configuration file), users were not
  vulnerable to this issue.

  This issue was discovered by Karel Volný of the Red Hat Quality Engineering
  team.

  This update also fixes the following bugs:

  * Prior to this update, the log file path in the logrotate script did not
  behave as expected. As a consequence, the logrotate function failed to
  rotate the '/var/log/mysqld.log' file. This update modifies the logrotate
  script to allow rotating the mysqld.log file. (BZ#647223)

  * Prior to this update, the mysqld daemon could fail when using the EXPLAIN
  flag in prepared statement mode. This update modifies the underlying code
  to handle the EXPLAIN flag as expected. (BZ#654000)

  * Prior to this update, the mysqld init script could wrongly report that
  mysql server startup failed when the server was actually started. This
  update modifies the init script to report the status of the mysqld server
  as expected. (BZ#703476)

  * Prior to this update, the '--enable-profiling' option was by default
  disabled. This update enables the profiling feature. (BZ#806365)

  All MySQL users are advised to upgrade to these updated packages, which
  contain backported patches to resolve these issues. After installing this
  update, the MySQL server daemon (mysqld) will be restarted automatically.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "CentOS5")
{

  if ((res = isrpmvuln(pkg:"mysql", rpm:"mysql~5.0.95~3.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mysql-bench", rpm:"mysql-bench~5.0.95~3.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mysql-devel", rpm:"mysql-devel~5.0.95~3.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mysql-server", rpm:"mysql-server~5.0.95~3.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mysql-test", rpm:"mysql-test~5.0.95~3.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
