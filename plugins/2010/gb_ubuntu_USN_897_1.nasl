###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_897_1.nasl 8287 2018-01-04 07:28:11Z teissa $
#
# Ubuntu Update for MySQL vulnerabilities USN-897-1
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
tag_insight = "It was discovered that MySQL could be made to overwrite existing table
  files in the data directory. An authenticated user could use the DATA
  DIRECTORY and INDEX DIRECTORY options to possibly bypass privilege checks.
  This update alters table creation behaviour by disallowing the use of the
  MySQL data directory in DATA DIRECTORY and INDEX DIRECTORY options. This
  issue only affected Ubuntu 8.10. (CVE-2008-4098)

  It was discovered that MySQL contained a cross-site scripting vulnerability
  in the command-line client when the --html option is enabled. An attacker
  could place arbitrary web script or html in a database cell, which would
  then get placed in the html document output by the command-line tool. This
  issue only affected Ubuntu 6.06 LTS, 8.04 LTS, 8.10 and 9.04.
  (CVE-2008-4456)
  
  It was discovered that MySQL could be made to overwrite existing table
  files in the data directory. An authenticated user could use symlinks
  combined with the DATA DIRECTORY and INDEX DIRECTORY options to possibly
  bypass privilege checks. This issue only affected Ubuntu 9.10.
  (CVE-2008-7247)
  
  It was discovered that MySQL contained multiple format string flaws when
  logging database creation and deletion. An authenticated user could use
  specially crafted database names to make MySQL crash, causing a denial of
  service. This issue only affected Ubuntu 6.06 LTS, 8.04 LTS, 8.10 and 9.04.
  (CVE-2009-2446)
  
  It was discovered that MySQL incorrectly handled errors when performing
  certain SELECT statements, and did not preserve correct flags when
  performing statements that use the GeomFromWKB function. An authenticated
  user could exploit this to make MySQL crash, causing a denial of service.
  (CVE-2009-4019)
  
  It was discovered that MySQL incorrectly checked symlinks when using the
  DATA DIRECTORY and INDEX DIRECTORY options. A local user could use symlinks
  to create tables that pointed to tables known to be created at a later
  time, bypassing access restrictions. (CVE-2009-4030)
  
  It was discovered that MySQL contained a buffer overflow when parsing
  ssl certificates. A remote attacker could send crafted requests and cause a
  denial of service or possibly execute arbitrary code. This issue did not
  affect Ubuntu 6.06 LTS and the default compiler options for affected
  releases should reduce the vulnerability to a denial of service. In the
  default installation, attackers would also be isolated by the AppArmor
  MySQL profile. (CVE-2009-4484)";

tag_summary = "Ubuntu Update for Linux kernel vulnerabilities USN-897-1";
tag_affected = "MySQL vulnerabilities on Ubuntu 6.06 LTS ,
  Ubuntu 8.04 LTS ,
  Ubuntu 8.10 ,
  Ubuntu 9.04 ,
  Ubuntu 9.10";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-897-1/");
  script_oid("1.3.6.1.4.1.25623.1.0.313505");
  script_version("$Revision: 8287 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-04 08:28:11 +0100 (Thu, 04 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-02-15 16:07:49 +0100 (Mon, 15 Feb 2010)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_cve_id("CVE-2008-4098", "CVE-2008-4456", "CVE-2008-7247", "CVE-2009-2446", "CVE-2009-4019", "CVE-2009-4030", "CVE-2009-4484");
  script_name("Ubuntu Update for MySQL vulnerabilities USN-897-1");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages");
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("pkg-lib-deb.inc");

release = get_kb_item("ssh/login/release");


res = "";
if(release == NULL){
  exit(0);
}

if(release == "UBUNTU9.04")
{

  if ((res = isdpkgvuln(pkg:"libmysqlclient15-dev", ver:"5.1.30really5.0.75-0ubuntu10.3", rls:"UBUNTU9.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libmysqlclient15off", ver:"5.1.30really5.0.75-0ubuntu10.3", rls:"UBUNTU9.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"mysql-client-5.0", ver:"5.1.30really5.0.75-0ubuntu10.3", rls:"UBUNTU9.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"mysql-server-5.0", ver:"5.1.30really5.0.75-0ubuntu10.3", rls:"UBUNTU9.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"mysql-server-core-5.0", ver:"5.1.30really5.0.75-0ubuntu10.3", rls:"UBUNTU9.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"mysql-client", ver:"5.1.30really5.0.75-0ubuntu10.3", rls:"UBUNTU9.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"mysql-common", ver:"5.1.30really5.0.75-0ubuntu10.3", rls:"UBUNTU9.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"mysql-server", ver:"5.1.30really5.0.75-0ubuntu10.3", rls:"UBUNTU9.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU6.06 LTS")
{

  if ((res = isdpkgvuln(pkg:"libmysqlclient15-dev", ver:"5.0.22-0ubuntu6.06.12", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libmysqlclient15off", ver:"5.0.22-0ubuntu6.06.12", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"mysql-client-5.0", ver:"5.0.22-0ubuntu6.06.12", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"mysql-server-5.0", ver:"5.0.22-0ubuntu6.06.12", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"mysql-client", ver:"5.0.22-0ubuntu6.06.12", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"mysql-common", ver:"5.0.22-0ubuntu6.06.12", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"mysql-server", ver:"5.0.22-0ubuntu6.06.12", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU8.10")
{

  if ((res = isdpkgvuln(pkg:"libmysqlclient15-dev", ver:"5.0.67-0ubuntu6.1", rls:"UBUNTU8.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libmysqlclient15off", ver:"5.0.67-0ubuntu6.1", rls:"UBUNTU8.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"mysql-client-5.0", ver:"5.0.67-0ubuntu6.1", rls:"UBUNTU8.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"mysql-server-5.0", ver:"5.0.67-0ubuntu6.1", rls:"UBUNTU8.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"mysql-client", ver:"5.0.67-0ubuntu6.1", rls:"UBUNTU8.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"mysql-common", ver:"5.0.67-0ubuntu6.1", rls:"UBUNTU8.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"mysql-server", ver:"5.0.67-0ubuntu6.1", rls:"UBUNTU8.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU8.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"libmysqlclient15-dev", ver:"5.0.51a-3ubuntu5.5", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libmysqlclient15off", ver:"5.0.51a-3ubuntu5.5", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"mysql-client-5.0", ver:"5.0.51a-3ubuntu5.5", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"mysql-server-5.0", ver:"5.0.51a-3ubuntu5.5", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"mysql-client", ver:"5.0.51a-3ubuntu5.5", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"mysql-common", ver:"5.0.51a-3ubuntu5.5", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"mysql-server", ver:"5.0.51a-3ubuntu5.5", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU9.10")
{

  if ((res = isdpkgvuln(pkg:"libmysqlclient-dev", ver:"5.1.37-1ubuntu5.1", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libmysqlclient16", ver:"5.1.37-1ubuntu5.1", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libmysqld-dev", ver:"5.1.37-1ubuntu5.1", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libmysqld-pic", ver:"5.1.37-1ubuntu5.1", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"mysql-client-5.1", ver:"5.1.37-1ubuntu5.1", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"mysql-server-5.1", ver:"5.1.37-1ubuntu5.1", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"mysql-server-core-5.1", ver:"5.1.37-1ubuntu5.1", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libmysqlclient16-dev", ver:"5.1.37-1ubuntu5.1", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"mysql-client", ver:"5.1.37-1ubuntu5.1", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"mysql-common", ver:"5.1.37-1ubuntu5.1", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"mysql-server", ver:"5.1.37-1ubuntu5.1", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
