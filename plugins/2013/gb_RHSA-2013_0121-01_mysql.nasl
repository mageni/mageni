###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for mysql RHSA-2013:0121-01
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
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2013-January/msg00004.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870888");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2013-01-11 16:42:46 +0530 (Fri, 11 Jan 2013)");
  script_cve_id("CVE-2012-4452", "CVE-2009-4030");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_name("RedHat Update for mysql RHSA-2013:0121-01");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mysql'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_5");
  script_tag(name:"affected", value:"mysql on Red Hat Enterprise Linux (v. 5 server)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
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

  This issue was discovered by Karel Volny of the Red Hat Quality Engineering
  team.

  This update also fixes the following bugs:

  * Prior to this update, the log file path in the logrotate script did not
  behave as expected. As a consequence, the logrotate function failed to
  rotate the '/var/log/mysqld.log' file. This update modifies the logrotate
  script to allow rotating the mysqld.log file. (BZ#647223)

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
if(!release) exit(0);

res = "";

if(release == "RHENT_5")
{

  if ((res = isrpmvuln(pkg:"mysql", rpm:"mysql~5.0.95~3.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mysql-bench", rpm:"mysql-bench~5.0.95~3.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mysql-debuginfo", rpm:"mysql-debuginfo~5.0.95~3.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mysql-devel", rpm:"mysql-devel~5.0.95~3.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mysql-server", rpm:"mysql-server~5.0.95~3.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mysql-test", rpm:"mysql-test~5.0.95~3.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
