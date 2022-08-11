###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for mysql RHSA-2008:0768-01
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_insight = "MySQL is a multi-user, multi-threaded SQL database server. MySQL is a
  client/server implementation consisting of a server daemon (mysqld), and
  many different client programs and libraries.

  MySQL did not correctly check directories used as arguments for the DATA
  DIRECTORY and INDEX DIRECTORY directives. Using this flaw, an authenticated
  attacker could elevate their access privileges to tables created by other
  database users. Note: this attack does not work on existing tables. An
  attacker can only elevate their access to another user's tables as the
  tables are created. As well, the names of these created tables need to be
  predicted correctly for this attack to succeed. (CVE-2008-2079)
  
  MySQL did not require the &quot;DROP&quot; privilege for &quot;RENAME TABLE&quot; statements.
  An authenticated user could use this flaw to rename arbitrary tables.
  (CVE-2007-2691)
  
  MySQL allowed an authenticated user to access a table through a previously
  created MERGE table, even after the user's privileges were revoked from the
  original table, which might violate intended security policy. This is
  addressed by allowing the MERGE storage engine to be disabled, which can be
  done by running mysqld with the &quot;--skip-merge&quot; option. (CVE-2006-4031)
  
  A flaw in MySQL allowed an authenticated user to cause the MySQL daemon to
  crash via crafted SQL queries. This only caused a temporary denial of
  service, as the MySQL daemon is automatically restarted after the crash.
  (CVE-2006-3469)
  
  As well, these updated packages fix the following bugs:
  
  * in the previous mysql packages, if a column name was referenced more
  than once in an &quot;ORDER BY&quot; section of a query, a segmentation fault
  occurred.
  
  * when MySQL failed to start, the init script returned a successful (0)
  exit code. When using the Red Hat Cluster Suite, this may have caused
  cluster services to report a successful start, even when MySQL failed to
  start. In these updated packages, the init script returns the correct exit
  codes, which resolves this issue.
  
  * it was possible to use the mysqld_safe command to specify invalid port
  numbers (higher than 65536), causing invalid ports to be created, and, in
  some cases, a &quot;port number definition: unsigned short&quot; error. In these
  updated packages, when an invalid port number is specified, the default
  port number is used.
  
  * when setting &quot;myisam_repair_threads &gt; 1&quot;, any repair set the index
  cardi ... 

  Description truncated, for more information please check the Reference URL";

tag_affected = "mysql on Red Hat Enterprise Linux AS version 4,
  Red Hat Enterprise Linux ES version 4,
  Red Hat Enterprise Linux WS version 4";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/rhsa-announce/2008-July/msg00034.html");
  script_oid("1.3.6.1.4.1.25623.1.0.308923");
  script_version("$Revision: 6683 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-12 11:41:57 +0200 (Wed, 12 Jul 2017) $");
  script_tag(name:"creation_date", value:"2009-03-06 07:30:35 +0100 (Fri, 06 Mar 2009)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:P");
  script_xref(name: "RHSA", value: "2008:0768-01");
  script_cve_id("CVE-2006-3469", "CVE-2006-4031", "CVE-2007-2691", "CVE-2008-2079");
  script_name( "RedHat Update for mysql RHSA-2008:0768-01");

  script_tag(name:"summary", value:"Check for the Version of mysql");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
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

  if ((res = isrpmvuln(pkg:"mysql", rpm:"mysql~4.1.22~2.el4", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mysql-bench", rpm:"mysql-bench~4.1.22~2.el4", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mysql-debuginfo", rpm:"mysql-debuginfo~4.1.22~2.el4", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mysql-devel", rpm:"mysql-devel~4.1.22~2.el4", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mysql-server", rpm:"mysql-server~4.1.22~2.el4", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
