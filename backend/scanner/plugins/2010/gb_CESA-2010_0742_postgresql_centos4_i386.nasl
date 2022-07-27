###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for postgresql CESA-2010:0742 centos4 i386
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
  Perl and Tcl languages. The PostgreSQL SECURITY DEFINER parameter, which
  can be used when creating a new PostgreSQL function, specifies that the
  function will be executed with the privileges of the user that created it.

  It was discovered that a user could utilize the features of the PL/Perl and
  PL/Tcl languages to modify the behavior of a SECURITY DEFINER function
  created by a different user. If the PL/Perl or PL/Tcl language was used to
  implement a SECURITY DEFINER function, an authenticated database user could
  use a PL/Perl or PL/Tcl script to modify the behavior of that function
  during subsequent calls in the same session. This would result in the
  modified or injected code also being executed with the privileges of the
  user who created the SECURITY DEFINER function, possibly leading to
  privilege escalation. (CVE-2010-3433)
  
  For Red Hat Enterprise Linux 4, the updated postgresql packages upgrade
  PostgreSQL to version 7.4.30. Refer to the PostgreSQL Release Notes for a
  list of changes:
  
  http://www.postgresql.org/docs/7.4/static/release.html
  
  For Red Hat Enterprise Linux 5, the updated postgresql packages upgrade
  PostgreSQL to version 8.1.22, and the updated postgresql84 packages upgrade
  PostgreSQL to version 8.4.5. Refer to the PostgreSQL Release Notes for a
  list of changes:
  
  http://www.postgresql.org/docs/8.1/static/release.html
  http://www.postgresql.org/docs/8.4/static/release.html
  
  All PostgreSQL users are advised to upgrade to these updated packages,
  which correct this issue. If the postgresql service is running, it will be
  automatically restarted after installing this update.";
tag_solution = "Please Install the Updated Packages.";

tag_affected = "postgresql on CentOS 4";


if(description)
{
  script_xref(name : "URL" , value : "http://lists.centos.org/pipermail/centos-announce/2010-October/017041.html");
  script_oid("1.3.6.1.4.1.25623.1.0.313054");
  script_version("$Revision: 8510 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-24 08:57:42 +0100 (Wed, 24 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-10-19 15:54:15 +0200 (Tue, 19 Oct 2010)");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_cve_id("CVE-2010-3433");
  script_name("CentOS Update for postgresql CESA-2010:0742 centos4 i386");

  script_tag(name: "summary" , value: "Check for the Version of postgresql");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms");
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
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

if(release == "CentOS4")
{

  if ((res = isrpmvuln(pkg:"postgresql", rpm:"postgresql~7.4.30~1.el4_8.1", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql-contrib", rpm:"postgresql-contrib~7.4.30~1.el4_8.1", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql-devel", rpm:"postgresql-devel~7.4.30~1.el4_8.1", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql-docs", rpm:"postgresql-docs~7.4.30~1.el4_8.1", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql-jdbc", rpm:"postgresql-jdbc~7.4.30~1.el4_8.1", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql-libs", rpm:"postgresql-libs~7.4.30~1.el4_8.1", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql-pl", rpm:"postgresql-pl~7.4.30~1.el4_8.1", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql-python", rpm:"postgresql-python~7.4.30~1.el4_8.1", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql-server", rpm:"postgresql-server~7.4.30~1.el4_8.1", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql-tcl", rpm:"postgresql-tcl~7.4.30~1.el4_8.1", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql-test", rpm:"postgresql-test~7.4.30~1.el4_8.1", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
