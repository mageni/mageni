###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_905_1.nasl 8510 2018-01-24 07:57:42Z teissa $
#
# Ubuntu Update for sudo vulnerabilities USN-905-1
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
tag_insight = "It was discovered that sudo did not properly validate the path for the
  'sudoedit' pseudo-command. A local attacker could exploit this to execute
  arbitrary code as root if sudo was configured to allow the attacker to use
  sudoedit. The sudoedit pseudo-command is not used in the default
  installation of Ubuntu. (CVE-2010-0426)

  It was discovered that sudo did not reset group permissions when the
  'runas_default' configuration option was used. A local attacker could
  exploit this to escalate group privileges if sudo was configured to allow
  the attacker to run commands under the runas_default account. The
  runas_default configuration option is not used in the default installation
  of Ubuntu. This issue affected Ubuntu 8.04 LTS, 8.10 and 9.04.
  (CVE-2010-0427)";

tag_summary = "Ubuntu Update for Linux kernel vulnerabilities USN-905-1";
tag_affected = "sudo vulnerabilities on Ubuntu 6.06 LTS ,
  Ubuntu 8.04 LTS ,
  Ubuntu 8.10 ,
  Ubuntu 9.04 ,
  Ubuntu 9.10";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-905-1/");
  script_oid("1.3.6.1.4.1.25623.1.0.314646");
  script_version("$Revision: 8510 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-24 08:57:42 +0100 (Wed, 24 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-03-02 08:46:47 +0100 (Tue, 02 Mar 2010)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2010-0426", "CVE-2010-0427");
  script_name("Ubuntu Update for sudo vulnerabilities USN-905-1");

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

  if ((res = isdpkgvuln(pkg:"sudo", ver:"1.6.9p17-1ubuntu3.1", rls:"UBUNTU9.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"sudo-ldap", ver:"1.6.9p17-1ubuntu3.1", rls:"UBUNTU9.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU6.06 LTS")
{

  if ((res = isdpkgvuln(pkg:"sudo", ver:"1.6.8p12-1ubuntu6.1", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"sudo-ldap", ver:"1.6.8p12-1ubuntu6.1", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU8.10")
{

  if ((res = isdpkgvuln(pkg:"sudo", ver:"1.6.9p17-1ubuntu2.2", rls:"UBUNTU8.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"sudo-ldap", ver:"1.6.9p17-1ubuntu2.2", rls:"UBUNTU8.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU8.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"sudo", ver:"1.6.9p10-1ubuntu3.6", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"sudo-ldap", ver:"1.6.9p10-1ubuntu3.6", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU9.10")
{

  if ((res = isdpkgvuln(pkg:"sudo", ver:"1.7.0-1ubuntu2.1", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"sudo-ldap", ver:"1.7.0-1ubuntu2.1", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
