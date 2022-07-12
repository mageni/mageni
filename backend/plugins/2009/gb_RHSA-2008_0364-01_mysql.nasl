###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for mysql RHSA-2008:0364-01
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

  MySQL did not require privileges such as &quot;SELECT&quot; for the source table in a
  &quot;CREATE TABLE LIKE&quot; statement. An authenticated user could obtain sensitive
  information, such as the table structure. (CVE-2007-3781)
  
  A flaw was discovered in MySQL that allowed an authenticated user to gain
  update privileges for a table in another database, via a view that refers
  to the external table. (CVE-2007-3782)
  
  MySQL did not require the &quot;DROP&quot; privilege for &quot;RENAME TABLE&quot; statements.
  An authenticated user could use this flaw to rename arbitrary tables.
  (CVE-2007-2691)
  
  A flaw was discovered in the mysql_change_db function when returning from
  SQL SECURITY INVOKER stored routines. An authenticated user could use this
  flaw to gain database privileges. (CVE-2007-2692)
  
  MySQL allowed an authenticated user to bypass logging mechanisms via SQL
  queries that contain the NULL character, which were not properly handled by
  the mysql_real_query function. (CVE-2006-0903)
  
  MySQL allowed an authenticated user to access a table through a previously
  created MERGE table, even after the user's privileges were revoked from
  the original table, which might violate intended security policy. This is
  addressed by allowing the MERGE storage engine to be disabled, which can
  be done by running mysqld with the &quot;--skip-merge&quot; option. (CVE-2006-4031)
  
  MySQL evaluated arguments in the wrong security context, which allowed an
  authenticated user to gain privileges through a routine that had been made
  available using &quot;GRANT EXECUTE&quot;. (CVE-2006-4227)
  
  Multiple flaws in MySQL allowed an authenticated user to cause the MySQL
  daemon to crash via crafted SQL queries. This only caused a temporary
  denial of service, as the MySQL daemon is automatically restarted after the
  crash. (CVE-2006-7232, CVE-2007-1420, CVE-2007-2583)
  
  As well, these updated packages fix the following bugs:
  
  * a separate counter was used for &quot;insert delayed&quot; statements, which caused
  rows to be discarded. In these updated packages, &quot;insert delayed&quot;
  statements no longer use a separate counter, which resolves this issue.
  
  * due to a bug in the Native POSIX Thread Library, in certain situations,
  &quot;flush tables&quot; caused a deadlock on tables that had a read lock. The mysqld
  daemon had to be ki ... 

  Description truncated, for more information please check the Reference URL";

tag_affected = "mysql on Red Hat Enterprise Linux (v. 5 server)";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/rhsa-announce/2008-May/msg00021.html");
  script_oid("1.3.6.1.4.1.25623.1.0.309710");
  script_version("$Revision: 6683 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-12 11:41:57 +0200 (Wed, 12 Jul 2017) $");
  script_tag(name:"creation_date", value:"2009-03-06 07:30:35 +0100 (Fri, 06 Mar 2009)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_xref(name: "RHSA", value: "2008:0364-01");
  script_cve_id("CVE-2006-0903", "CVE-2006-4031", "CVE-2006-4227", "CVE-2006-7232", "CVE-2007-1420", "CVE-2007-2583", "CVE-2007-2691", "CVE-2007-2692", "CVE-2007-3781", "CVE-2007-3782");
  script_name( "RedHat Update for mysql RHSA-2008:0364-01");

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

if(release == "RHENT_5")
{

  if ((res = isrpmvuln(pkg:"mysql", rpm:"mysql~5.0.45~7.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mysql-bench", rpm:"mysql-bench~5.0.45~7.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mysql-debuginfo", rpm:"mysql-debuginfo~5.0.45~7.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mysql-devel", rpm:"mysql-devel~5.0.45~7.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mysql-server", rpm:"mysql-server~5.0.45~7.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mysql-test", rpm:"mysql-test~5.0.45~7.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
