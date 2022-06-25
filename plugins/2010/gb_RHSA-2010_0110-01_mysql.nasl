###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for mysql RHSA-2010:0110-01
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

  Multiple flaws were discovered in the way MySQL handled symbolic links to
  tables created using the DATA DIRECTORY and INDEX DIRECTORY directives in
  CREATE TABLE statements. An attacker with CREATE and DROP table privileges
  and shell access to the database server could use these flaws to escalate
  their database privileges, or gain access to tables created by other
  database users. (CVE-2008-4098, CVE-2009-4030)
  
  Note: Due to the security risks and previous security issues related to the
  use of the DATA DIRECTORY and INDEX DIRECTORY directives, users not
  depending on this feature should consider disabling it by adding
  &quot;symbolic-links=0&quot; to the &quot;[mysqld]&quot; section of the &quot;my.cnf&quot; configuration
  file. In this update, an example of such a configuration was added to the
  default &quot;my.cnf&quot; file.
  
  An insufficient HTML entities quoting flaw was found in the mysql command
  line client's HTML output mode. If an attacker was able to inject arbitrary
  HTML tags into data stored in a MySQL database, which was later retrieved
  using the mysql command line client and its HTML output mode, they could
  perform a cross-site scripting (XSS) attack against victims viewing the
  HTML output in a web browser. (CVE-2008-4456)
  
  Multiple format string flaws were found in the way the MySQL server logged
  user commands when creating and deleting databases. A remote, authenticated
  attacker with permissions to CREATE and DROP databases could use these
  flaws to formulate a specially-crafted SQL command that would cause a
  temporary denial of service (open connections to mysqld are terminated).
  (CVE-2009-2446)
  
  Note: To exploit the CVE-2009-2446 flaws, the general query log (the mysqld
  &quot;--log&quot; command line option or the &quot;log&quot; option in &quot;my.cnf&quot;) must be
  enabled. This logging is not enabled by default.
  
  All MySQL users are advised to upgrade to these updated packages, which
  contain backported patches to resolve these issues. After installing this
  update, the MySQL server daemon (mysqld) will be restarted automatically.";

tag_affected = "mysql on Red Hat Enterprise Linux AS version 4,
  Red Hat Enterprise Linux ES version 4,
  Red Hat Enterprise Linux WS version 4";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/rhsa-announce/2010-February/msg00009.html");
  script_oid("1.3.6.1.4.1.25623.1.0.314744");
  script_version("$Revision: 8258 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-29 08:28:57 +0100 (Fri, 29 Dec 2017) $");
  script_tag(name:"creation_date", value:"2010-02-19 13:38:15 +0100 (Fri, 19 Feb 2010)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_xref(name: "RHSA", value: "2010:0110-01");
  script_cve_id("CVE-2008-4098", "CVE-2008-4456", "CVE-2009-2446", "CVE-2009-4030", "CVE-2008-2079");
  script_name("RedHat Update for mysql RHSA-2010:0110-01");

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

if(release == "RHENT_4")
{

  if ((res = isrpmvuln(pkg:"mysql", rpm:"mysql~4.1.22~2.el4_8.3", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mysql-bench", rpm:"mysql-bench~4.1.22~2.el4_8.3", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mysql-debuginfo", rpm:"mysql-debuginfo~4.1.22~2.el4_8.3", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mysql-devel", rpm:"mysql-devel~4.1.22~2.el4_8.3", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mysql-server", rpm:"mysql-server~4.1.22~2.el4_8.3", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
