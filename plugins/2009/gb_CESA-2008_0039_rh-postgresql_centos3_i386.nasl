###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for rh-postgresql CESA-2008:0039 centos3 i386
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
tag_insight = "PostgreSQL is an advanced Object-Relational database management system
  (DBMS). The postgresql packages include the client programs and libraries
  needed to access a PostgreSQL DBMS server.

  A privilege escalation flaw was discovered in PostgreSQL. An authenticated
  attacker could create an index function that would be executed with
  administrator privileges during database maintenance tasks, such as
  database vacuuming. (CVE-2007-6600)
  
  A privilege escalation flaw was discovered in PostgreSQL's Database Link
  library (dblink). An authenticated attacker could use dblink to possibly
  escalate privileges on systems with &quot;trust&quot; or &quot;ident&quot; authentication
  configured. Please note that dblink functionality is not enabled by
  default, and can only by enabled by a database administrator on systems
  with the postgresql-contrib package installed.
  (CVE-2007-3278, CVE-2007-6601)
  
  All postgresql users should upgrade to these updated packages, which
  include PostgreSQL 7.3.21 and resolve these issues.";

tag_affected = "rh-postgresql on CentOS 3";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.centos.org/pipermail/centos-announce/2008-January/014571.html");
  script_oid("1.3.6.1.4.1.25623.1.0.309889");
  script_version("$Revision: 6651 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-10 13:45:21 +0200 (Mon, 10 Jul 2017) $");
  script_tag(name:"creation_date", value:"2009-02-27 09:02:20 +0100 (Fri, 27 Feb 2009)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2007-3278", "CVE-2007-6600", "CVE-2007-6601");
  script_name( "CentOS Update for rh-postgresql CESA-2008:0039 centos3 i386");

  script_tag(name:"summary", value:"Check for the Version of rh-postgresql");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms");
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

if(release == "CentOS3")
{

  if ((res = isrpmvuln(pkg:"rh-postgresql", rpm:"rh-postgresql~7.3.21~1", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"rh-postgresql-contrib", rpm:"rh-postgresql-contrib~7.3.21~1", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"rh-postgresql-devel", rpm:"rh-postgresql-devel~7.3.21~1", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"rh-postgresql-docs", rpm:"rh-postgresql-docs~7.3.21~1", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"rh-postgresql-jdbc", rpm:"rh-postgresql-jdbc~7.3.21~1", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"rh-postgresql-libs", rpm:"rh-postgresql-libs~7.3.21~1", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"rh-postgresql-pl", rpm:"rh-postgresql-pl~7.3.21~1", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"rh-postgresql-python", rpm:"rh-postgresql-python~7.3.21~1", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"rh-postgresql-server", rpm:"rh-postgresql-server~7.3.21~1", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"rh-postgresql-tcl", rpm:"rh-postgresql-tcl~7.3.21~1", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"rh-postgresql-test", rpm:"rh-postgresql-test~7.3.21~1", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
