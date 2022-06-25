###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1017_1.nasl 8510 2018-01-24 07:57:42Z teissa $
#
# Ubuntu Update for MySQL vulnerabilities USN-1017-1
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
tag_insight = "It was discovered that MySQL incorrectly handled certain requests with the
  UPGRADE DATA DIRECTORY NAME command. An authenticated user could exploit
  this to make MySQL crash, causing a denial of service. This issue only
  affected Ubuntu 9.10 and 10.04 LTS. (CVE-2010-2008)

  It was discovered that MySQL incorrectly handled joins involving a table
  with a unique SET column. An authenticated user could exploit this to make
  MySQL crash, causing a denial of service. This issue only affected Ubuntu
  6.06 LTS, 8.04 LTS, 9.10 and 10.04 LTS. (CVE-2010-3677)
  
  It was discovered that MySQL incorrectly handled NULL arguments to IN() or
  CASE operations. An authenticated user could exploit this to make MySQL
  crash, causing a denial of service. This issue only affected Ubuntu 9.10
  and 10.04 LTS. (CVE-2010-3678)
  
  It was discovered that MySQL incorrectly handled malformed arguments to the
  BINLOG statement. An authenticated user could exploit this to make MySQL
  crash, causing a denial of service. This issue only affected Ubuntu 9.10
  and 10.04 LTS. (CVE-2010-3679)
  
  It was discovered that MySQL incorrectly handled the use of TEMPORARY
  InnoDB tables with nullable columns. An authenticated user could exploit
  this to make MySQL crash, causing a denial of service. This issue only
  affected Ubuntu 6.06 LTS, 8.04 LTS, 9.10 and 10.04 LTS. (CVE-2010-3680)
  
  It was discovered that MySQL incorrectly handled alternate reads from two
  indexes on a table using the HANDLER interface. An authenticated user could
  exploit this to make MySQL crash, causing a denial of service. This issue
  only affected Ubuntu 6.06 LTS, 8.04 LTS, 9.10 and 10.04 LTS.
  (CVE-2010-3681)
  
  It was discovered that MySQL incorrectly handled use of EXPLAIN with
  certain queries. An authenticated user could exploit this to make MySQL
  crash, causing a denial of service. This issue only affected Ubuntu
  6.06 LTS, 8.04 LTS, 9.10 and 10.04 LTS. (CVE-2010-3682)
  
  It was discovered that MySQL incorrectly handled error reporting when using
  LOAD DATA INFILE and would incorrectly raise an assert in certain
  circumstances. An authenticated user could exploit this to make MySQL
  crash, causing a denial of service. This issue only affected Ubuntu 9.10
  and 10.04 LTS. (CVE-2010-3683)
  
  It was discovered that MySQL incorrectly handled propagation during
  evaluation of arguments to extreme-value functions. An authenticated user
  could exploit this to make MySQL crash, causing a denial of service. This
  issue only affected Ubuntu 8.0 ... 

  Description truncated, for more information please check the Reference URL";

tag_summary = "Ubuntu Update for Linux kernel vulnerabilities USN-1017-1";
tag_affected = "MySQL vulnerabilities on Ubuntu 6.06 LTS ,
  Ubuntu 8.04 LTS ,
  Ubuntu 9.10 ,
  Ubuntu 10.04 LTS";
tag_solution = "Please Install the Updated Packages.";


if(description)
{
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-1017-1/");
  script_oid("1.3.6.1.4.1.25623.1.0.312899");
  script_version("$Revision: 8510 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-24 08:57:42 +0100 (Wed, 24 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-11-16 14:49:48 +0100 (Tue, 16 Nov 2010)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2010-2008", "CVE-2010-3677", "CVE-2010-3678", "CVE-2010-3679", "CVE-2010-3680", "CVE-2010-3681", "CVE-2010-3682", "CVE-2010-3683", "CVE-2010-3833", "CVE-2010-3834", "CVE-2010-3835", "CVE-2010-3836", "CVE-2010-3837", "CVE-2010-3838", "CVE-2010-3839", "CVE-2010-3840");
  script_name("Ubuntu Update for MySQL vulnerabilities USN-1017-1");

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

if(release == "UBUNTU9.10")
{

  if ((res = isdpkgvuln(pkg:"libmysqlclient-dev", ver:"5.1.37-1ubuntu5.5", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libmysqlclient16", ver:"5.1.37-1ubuntu5.5", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libmysqld-dev", ver:"5.1.37-1ubuntu5.5", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libmysqld-pic", ver:"5.1.37-1ubuntu5.5", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"mysql-client-5.1", ver:"5.1.37-1ubuntu5.5", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"mysql-server-5.1", ver:"5.1.37-1ubuntu5.5", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"mysql-server-core-5.1", ver:"5.1.37-1ubuntu5.5", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libmysqlclient16-dev", ver:"5.1.37-1ubuntu5.5", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"mysql-client", ver:"5.1.37-1ubuntu5.5", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"mysql-common", ver:"5.1.37-1ubuntu5.5", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"mysql-server", ver:"5.1.37-1ubuntu5.5", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU6.06 LTS")
{

  if ((res = isdpkgvuln(pkg:"libmysqlclient15-dev", ver:"5.0.22-0ubuntu6.06.15", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libmysqlclient15off", ver:"5.0.22-0ubuntu6.06.15", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"mysql-client-5.0", ver:"5.0.22-0ubuntu6.06.15", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"mysql-server-5.0", ver:"5.0.22-0ubuntu6.06.15", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"mysql-client", ver:"5.0.22-0ubuntu6.06.15", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"mysql-common", ver:"5.0.22-0ubuntu6.06.15", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"mysql-server", ver:"5.0.22-0ubuntu6.06.15", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU10.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"libmysqlclient-dev", ver:"5.1.41-3ubuntu12.7", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libmysqlclient16", ver:"5.1.41-3ubuntu12.7", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libmysqld-dev", ver:"5.1.41-3ubuntu12.7", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libmysqld-pic", ver:"5.1.41-3ubuntu12.7", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"mysql-client-5.1", ver:"5.1.41-3ubuntu12.7", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"mysql-client-core-5.1", ver:"5.1.41-3ubuntu12.7", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"mysql-server-5.1", ver:"5.1.41-3ubuntu12.7", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"mysql-server-core-5.1", ver:"5.1.41-3ubuntu12.7", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"mysql-testsuite", ver:"5.1.41-3ubuntu12.7", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libmysqlclient16-dev", ver:"5.1.41-3ubuntu12.7", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"mysql-client", ver:"5.1.41-3ubuntu12.7", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"mysql-common", ver:"5.1.41-3ubuntu12.7", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"mysql-server", ver:"5.1.41-3ubuntu12.7", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU8.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"libmysqlclient15-dev", ver:"5.0.51a-3ubuntu5.8", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libmysqlclient15off", ver:"5.0.51a-3ubuntu5.8", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"mysql-client-5.0", ver:"5.0.51a-3ubuntu5.8", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"mysql-server-5.0", ver:"5.0.51a-3ubuntu5.8", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"mysql-client", ver:"5.0.51a-3ubuntu5.8", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"mysql-common", ver:"5.0.51a-3ubuntu5.8", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"mysql-server", ver:"5.0.51a-3ubuntu5.8", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
