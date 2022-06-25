###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for postgresql RHSA-2010:0427-01
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
tag_insight = "PostgreSQL is an advanced object-relational database management system
  (DBMS). PL/Perl and PL/Tcl allow users to write PostgreSQL functions in the
  Perl and Tcl languages, and are installed in trusted mode by default. In
  trusted mode, certain operations, such as operating system level access,
  are restricted.

  A flaw was found in the way PostgreSQL enforced permission checks on
  scripts written in PL/Perl. If the PL/Perl procedural language was
  registered on a particular database, an authenticated database user running
  a specially-crafted PL/Perl script could use this flaw to bypass intended
  PL/Perl trusted mode restrictions, allowing them to run arbitrary Perl
  scripts with the privileges of the database server. (CVE-2010-1169)
  
  Red Hat would like to thank Tim Bunce for responsibly reporting the
  CVE-2010-1169 flaw.
  
  A flaw was found in the way PostgreSQL enforced permission checks on
  scripts written in PL/Tcl. If the PL/Tcl procedural language was registered
  on a particular database, an authenticated database user running a
  specially-crafted PL/Tcl script could use this flaw to bypass intended
  PL/Tcl trusted mode restrictions, allowing them to run arbitrary Tcl
  scripts with the privileges of the database server. (CVE-2010-1170)
  
  A buffer overflow flaw was found in the way PostgreSQL retrieved a
  substring from the bit string for BIT() and BIT VARYING() SQL data types.
  An authenticated database user running a specially-crafted SQL query could
  use this flaw to cause a temporary denial of service (postgres daemon
  crash) or, potentially, execute arbitrary code with the privileges of the
  database server. (CVE-2010-0442)
  
  An integer overflow flaw was found in the way PostgreSQL used to calculate
  the size of the hash table for joined relations. An authenticated database
  user could create a specially-crafted SQL query which could cause a
  temporary denial of service (postgres daemon crash) or, potentially,
  execute arbitrary code with the privileges of the database server.
  (CVE-2010-0733)
  
  PostgreSQL improperly protected session-local state during the execution of
  an index function by a database superuser during the database maintenance
  operations. An authenticated database user could use this flaw to elevate
  their privileges via specially-crafted index functions. (CVE-2009-4136)
  
  All PostgreSQL users are advised to upgrade to these updated packages,
  which contain backported patches to correct these issues. Running
  PostgreSQL instances must be restarted (&quot;service rhdb restart&quot;) for this
  update to take effect.";

tag_affected = "postgresql on Red Hat Enterprise Linux AS version 3,
  Red Hat Enterprise Linux ES version 3,
  Red Hat Enterprise Linux WS version 3";
tag_solution = "Please Install the Updated Packages.";


if(description)
{
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/rhsa-announce/2010-May/msg00010.html");
  script_oid("1.3.6.1.4.1.25623.1.0.313437");
  script_version("$Revision: 8485 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-22 08:57:57 +0100 (Mon, 22 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-05-28 10:00:59 +0200 (Fri, 28 May 2010)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_xref(name: "RHSA", value: "2010:0427-01");
  script_cve_id("CVE-2009-4136", "CVE-2010-0442", "CVE-2010-0733", "CVE-2010-1169", "CVE-2010-1170");
  script_name("RedHat Update for postgresql RHSA-2010:0427-01");

  script_tag(name: "summary" , value: "Check for the Version of postgresql");
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

if(release == "RHENT_3")
{

  if ((res = isrpmvuln(pkg:"rh-postgresql", rpm:"rh-postgresql~7.3.21~3", rls:"RHENT_3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"rh-postgresql-contrib", rpm:"rh-postgresql-contrib~7.3.21~3", rls:"RHENT_3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"rh-postgresql-debuginfo", rpm:"rh-postgresql-debuginfo~7.3.21~3", rls:"RHENT_3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"rh-postgresql-devel", rpm:"rh-postgresql-devel~7.3.21~3", rls:"RHENT_3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"rh-postgresql-docs", rpm:"rh-postgresql-docs~7.3.21~3", rls:"RHENT_3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"rh-postgresql-jdbc", rpm:"rh-postgresql-jdbc~7.3.21~3", rls:"RHENT_3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"rh-postgresql-libs", rpm:"rh-postgresql-libs~7.3.21~3", rls:"RHENT_3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"rh-postgresql-pl", rpm:"rh-postgresql-pl~7.3.21~3", rls:"RHENT_3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"rh-postgresql-python", rpm:"rh-postgresql-python~7.3.21~3", rls:"RHENT_3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"rh-postgresql-server", rpm:"rh-postgresql-server~7.3.21~3", rls:"RHENT_3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"rh-postgresql-tcl", rpm:"rh-postgresql-tcl~7.3.21~3", rls:"RHENT_3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"rh-postgresql-test", rpm:"rh-postgresql-test~7.3.21~3", rls:"RHENT_3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
