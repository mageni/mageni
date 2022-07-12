###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for mysql RHSA-2010:0109-01
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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

include("revisions-lib.inc");
tag_insight = "MySQL is a multi-user, multi-threaded SQL database server. It consists of
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
  
  When the &quot;datadir&quot; option was configured with a relative path, MySQL did
  not properly check paths used as arguments for the DATA DIRECTORY and INDEX
  DIRECTORY directives. An authenticated attacker could use this flaw to
  bypass the restriction preventing the use of subdirectories of the MySQL
  data directory being used as DATA DIRECTORY and INDEX DIRECTORY paths.
  (CVE-2009-4030)
  
  Note: Due to the security risks and previous security issues related to the
  use of the DATA DIRECTORY and INDEX DIRECTORY directives, users not
  depending on this feature should consider disabling it by adding
  &quot;symbolic-links=0&quot; to the &quot;[mysqld]&quot; section of the &quot;my.cnf&quot; configuration
  file. In this update, an example of such a configuration was added to the
  default &quot;my.cnf&quot; file.
  
  All MySQL users are advised to upgrade to these updated packages, which
  contain backported patches to resolve these issues. After installing this
  update, the MySQL server daemon (mysqld) will be restarted automatically.";

tag_affected = "mysql on Red Hat Enterprise Linux (v. 5 server)";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/rhsa-announce/2010-February/msg00008.html");
  script_oid("1.3.6.1.4.1.25623.1.0.313428");
  script_version("$Revision: 8168 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-19 08:30:15 +0100 (Tue, 19 Dec 2017) $");
  script_tag(name:"creation_date", value:"2010-02-19 13:38:15 +0100 (Fri, 19 Feb 2010)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_xref(name: "RHSA", value: "2010:0109-01");
  script_cve_id("CVE-2009-4019", "CVE-2009-4028", "CVE-2009-4030", "CVE-2008-2079", "CVE-2008-4098");
  script_name("RedHat Update for mysql RHSA-2010:0109-01");

  script_tag(name: "summary" , value: "Check for the Version of mysql");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms");
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");


res = "";
if(release == NULL){
  exit(0);
}

if(release == "RHENT_5")
{

  if ((res = isrpmvuln(pkg:"mysql", rpm:"mysql~5.0.77~4.el5_4.2", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mysql-bench", rpm:"mysql-bench~5.0.77~4.el5_4.2", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mysql-debuginfo", rpm:"mysql-debuginfo~5.0.77~4.el5_4.2", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mysql-devel", rpm:"mysql-devel~5.0.77~4.el5_4.2", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mysql-server", rpm:"mysql-server~5.0.77~4.el5_4.2", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mysql-test", rpm:"mysql-test~5.0.77~4.el5_4.2", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
