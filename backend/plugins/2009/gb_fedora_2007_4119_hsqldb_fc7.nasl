###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for hsqldb FEDORA-2007-4119
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
tag_affected = "hsqldb on Fedora 7";
tag_insight = "HSQLdb is a relational database engine written in JavaTM , with a JDBC
  driver, supporting a subset of ANSI-92 SQL. It offers a small (about
  100k), fast database engine which offers both in memory and disk based
  tables. Embedded and server modes are available. Additionally, it
  includes tools such as a minimal web server, in-memory query and
  management tools (can be run as applets or servlets, too) and a number
  of demonstration examples.
  Downloaded code should be regarded as being of production quality. The
  product is currently being used as a database and persistence engine in
  many Open Source Software projects and even in commercial projects and
  products! In it's current version it is extremely stable and reliable.
  It is best known for its small size, ability to execute completely in
  memory and its speed. Yet it is a completely functional relational
  database management system that is completely free under the Modified
  BSD License. Yes, that's right, completely free of cost or restrictions!";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/fedora-package-announce/2008-January/msg00753.html");
  script_oid("1.3.6.1.4.1.25623.1.0.305242");
  script_version("$Revision: 6623 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-10 08:10:20 +0200 (Mon, 10 Jul 2017) $");
  script_tag(name:"creation_date", value:"2009-02-24 14:29:46 +0100 (Tue, 24 Feb 2009)");
  script_xref(name: "FEDORA", value: "2007-4119");
  script_cve_id("CVE-2007-4575");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name( "Fedora Update for hsqldb FEDORA-2007-4119");

  script_tag(name:"summary", value:"Check for the Version of hsqldb");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms");
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

if(release == "FC7")
{

  if ((res = isrpmvuln(pkg:"hsqldb", rpm:"hsqldb~1.8.0.8~1jpp.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"hsqldb", rpm:"hsqldb~1.8.0.8~1jpp.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"hsqldb-manual", rpm:"hsqldb-manual~1.8.0.8~1jpp.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"hsqldb-demo", rpm:"hsqldb-demo~1.8.0.8~1jpp.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"hsqldb-debuginfo", rpm:"hsqldb-debuginfo~1.8.0.8~1jpp.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"hsqldb-javadoc", rpm:"hsqldb-javadoc~1.8.0.8~1jpp.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"hsqldb-javadoc", rpm:"hsqldb-javadoc~1.8.0.8~1jpp.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"hsqldb-demo", rpm:"hsqldb-demo~1.8.0.8~1jpp.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"hsqldb-debuginfo", rpm:"hsqldb-debuginfo~1.8.0.8~1jpp.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"hsqldb", rpm:"hsqldb~1.8.0.8~1jpp.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"hsqldb-manual", rpm:"hsqldb-manual~1.8.0.8~1jpp.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}