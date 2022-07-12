###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for mysql CESA-2010:0109 centos5 i386
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2010-March/016527.html");
  script_oid("1.3.6.1.4.1.25623.1.0.880613");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-4019", "CVE-2009-4028", "CVE-2009-4030", "CVE-2008-2079", "CVE-2008-4098");
  script_name("CentOS Update for mysql CESA-2010:0109 centos5 i386");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mysql'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  script_tag(name:"affected", value:"mysql on CentOS 5");
  script_tag(name:"insight", value:"MySQL is a multi-user, multi-threaded SQL database server. It consists of
  the MySQL server daemon (mysqld) and many client programs and libraries.

  It was discovered that the MySQL client ignored certain SSL certificate
  verification errors when connecting to servers. A man-in-the-middle
  attacker could use this flaw to trick MySQL clients into connecting to a
  spoofed MySQL server. (CVE-2009-4028)

  Note: This fix may uncover previously hidden SSL configuration issues, such
  as incorrect CA certificates being used by clients or expired server
  certificates. This update should be carefully tested in deployments where
  SSL connections are used.

  A flaw was found in the way MySQL handled SELECT statements with subqueries
  in the WHERE clause, that assigned results to a user variable. A remote,
  authenticated attacker could use this flaw to crash the MySQL server daemon
  (mysqld). This issue only caused a temporary denial of service, as the
  MySQL daemon was automatically restarted after the crash. (CVE-2009-4019)

  When the 'datadir' option was configured with a relative path, MySQL did
  not properly check paths used as arguments for the DATA DIRECTORY and INDEX
  DIRECTORY directives. An authenticated attacker could use this flaw to
  bypass the restriction preventing the use of subdirectories of the MySQL
  data directory being used as DATA DIRECTORY and INDEX DIRECTORY paths.
  (CVE-2009-4030)

  Note: Due to the security risks and previous security issues related to the
  use of the DATA DIRECTORY and INDEX DIRECTORY directives, users not
  depending on this feature should consider disabling it by adding
  'symbolic-links=0' to the '[mysqld]' section of the 'my.cnf' configuration
  file. In this update, an example of such a configuration was added to the
  default 'my.cnf' file.

  All MySQL users are advised to upgrade to these updated packages, which
  contain backported patches to resolve these issues. After installing this
  update, the MySQL server daemon (mysqld) will be restarted automatically.");
  script_tag(name:"solution", value:"Please install the updated packages.");
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

  if ((res = isrpmvuln(pkg:"mysql", rpm:"mysql~5.0.77~4.el5_4.2", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mysql-bench", rpm:"mysql-bench~5.0.77~4.el5_4.2", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mysql-devel", rpm:"mysql-devel~5.0.77~4.el5_4.2", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mysql-server", rpm:"mysql-server~5.0.77~4.el5_4.2", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mysql-test", rpm:"mysql-test~5.0.77~4.el5_4.2", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
