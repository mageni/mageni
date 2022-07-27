###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for mysql RHSA-2010:0825-01
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

  It was found that the MySQL PolyFromWKB() function did not sanity check
  Well-Known Binary (WKB) data. A remote, authenticated attacker could use
  specially-crafted WKB data to crash mysqld. This issue only caused a
  temporary denial of service, as mysqld was automatically restarted after
  the crash. (CVE-2010-3840)
  
  A flaw was found in the way MySQL processed certain JOIN queries. If a
  stored procedure contained JOIN queries, and that procedure was executed
  twice in sequence, it could cause an infinite loop, leading to excessive
  CPU use (up to 100%). A remote, authenticated attacker could use this flaw
  to cause a denial of service. (CVE-2010-3839)
  
  A flaw was found in the way MySQL processed queries that provide a mixture
  of numeric and longblob data types to the LEAST or GREATEST function. A
  remote, authenticated attacker could use this flaw to crash mysqld. This
  issue only caused a temporary denial of service, as mysqld was
  automatically restarted after the crash. (CVE-2010-3838)
  
  A flaw was found in the way MySQL processed PREPARE statements containing
  both GROUP_CONCAT and the WITH ROLLUP modifier. A remote, authenticated
  attacker could use this flaw to crash mysqld. This issue only caused a
  temporary denial of service, as mysqld was automatically restarted after
  the crash. (CVE-2010-3837)
  
  It was found that MySQL did not properly pre-evaluate LIKE arguments in
  view prepare mode. A remote, authenticated attacker could possibly use this
  flaw to crash mysqld. (CVE-2010-3836)
  
  A flaw was found in the way MySQL processed statements that assign a value
  to a user-defined variable and that also contain a logical value
  evaluation. A remote, authenticated attacker could use this flaw to crash
  mysqld. This issue only caused a temporary denial of service, as mysqld was
  automatically restarted after the crash. (CVE-2010-3835)
  
  A flaw was found in the way MySQL evaluated the arguments of extreme-value
  functions, such as LEAST and GREATEST. A remote, authenticated attacker
  could use this flaw to crash mysqld. This issue only caused a temporary
  denial of service, as mysqld was automatically restarted after the crash.
  (CVE-2010-3833)
  
  A flaw was found in the way MySQL processed EXPLAIN statements for some
  complex SELECT queries. A remote, authenticated attacker could use this
  flaw to crash mysqld. This issue only caused a temporary denial of servic ... 

  Description truncated, for more information please check the Reference URL";

tag_affected = "mysql on Red Hat Enterprise Linux (v. 5 server)";
tag_solution = "Please Install the Updated Packages.";


if(description)
{
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/rhsa-announce/2010-November/msg00003.html");
  script_oid("1.3.6.1.4.1.25623.1.0.313357");
  script_version("$Revision: 8356 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-10 09:00:39 +0100 (Wed, 10 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-11-16 14:49:48 +0100 (Tue, 16 Nov 2010)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_xref(name: "RHSA", value: "2010:0825-01");
  script_cve_id("CVE-2010-3677", "CVE-2010-3680", "CVE-2010-3681", "CVE-2010-3682", "CVE-2010-3833", "CVE-2010-3835", "CVE-2010-3836", "CVE-2010-3837", "CVE-2010-3838", "CVE-2010-3839", "CVE-2010-3840");
  script_name("RedHat Update for mysql RHSA-2010:0825-01");

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

  if ((res = isrpmvuln(pkg:"mysql", rpm:"mysql~5.0.77~4.el5_5.4", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mysql-bench", rpm:"mysql-bench~5.0.77~4.el5_5.4", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mysql-debuginfo", rpm:"mysql-debuginfo~5.0.77~4.el5_5.4", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mysql-devel", rpm:"mysql-devel~5.0.77~4.el5_5.4", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mysql-server", rpm:"mysql-server~5.0.77~4.el5_5.4", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mysql-test", rpm:"mysql-test~5.0.77~4.el5_5.4", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
