###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_626_2.nasl 7969 2017-12-01 09:23:16Z santu $
#
# Ubuntu Update for devhelp, epiphany-browser, midbrowser, yelp update USN-626-2
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
tag_insight = "USN-626-1 fixed vulnerabilities in xulrunner-1.9. The changes required
  that Devhelp, Epiphany, Midbrowser and Yelp also be updated to use the
  new xulrunner-1.9.

  Original advisory details:
  
  A flaw was discovered in the browser engine. A variable could be made to
  overflow causing the browser to crash. If a user were tricked into opening
  a malicious web page, an attacker could cause a denial of service or
  possibly execute arbitrary code with the privileges of the user invoking
  the program. (CVE-2008-2785)
  
  Billy Rios discovered that Firefox and xulrunner, as used by browsers
  such as Epiphany, did not properly perform URI splitting with pipe
  symbols when passed a command-line URI. If Firefox or xulrunner were
  passed a malicious URL, an attacker may be able to execute local
  content with chrome privileges. (CVE-2008-2933)";

tag_summary = "Ubuntu Update for Linux kernel vulnerabilities USN-626-2";
tag_affected = "devhelp, epiphany-browser, midbrowser, yelp update on Ubuntu 8.04 LTS";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-626-2/");
  script_oid("1.3.6.1.4.1.25623.1.0.311046");
  script_version("$Revision: 7969 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-01 10:23:16 +0100 (Fri, 01 Dec 2017) $");
  script_tag(name:"creation_date", value:"2009-03-23 10:59:50 +0100 (Mon, 23 Mar 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-2785", "CVE-2008-2933");
  script_name( "Ubuntu Update for devhelp, epiphany-browser, midbrowser, yelp update USN-626-2");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
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

if(release == "UBUNTU8.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"devhelp", ver:"0.19-1ubuntu1.8.04.3", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libdevhelp-1-0", ver:"0.19-1ubuntu1.8.04.3", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libdevhelp-1-dev", ver:"0.19-1ubuntu1.8.04.3", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"epiphany-browser-dbg", ver:"2.22.2-0ubuntu0.8.04.5", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"epiphany-gecko", ver:"2.22.2-0ubuntu0.8.04.5", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"midbrowser", ver:"0.3.0rc1a-1~8.04.2", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"yelp", ver:"2.22.1-0ubuntu2.8.04.2", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"devhelp-common", ver:"0.19-1ubuntu1.8.04.3", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"epiphany-browser-data", ver:"2.22.2-0ubuntu0.8.04.5", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"epiphany-browser-dev", ver:"2.22.2-0ubuntu0.8.04.5", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"epiphany-browser", ver:"2.22.2-0ubuntu0.8.04.5", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
