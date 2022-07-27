###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1006_1.nasl 8287 2018-01-04 07:28:11Z teissa $
#
# Ubuntu Update for webkit vulnerabilities USN-1006-1
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
tag_insight = "A large number of security issues were discovered in the WebKit browser and
  JavaScript engines. If a user were tricked into viewing a malicious
  website, a remote attacker could exploit a variety of issues related to web
  browser security, including cross-site scripting attacks, denial of
  service attacks, and arbitrary code execution.

  Please consult the bug listed at the top of this advisory to get the exact
  list of CVE numbers fixed for each release.";

tag_summary = "Ubuntu Update for Linux kernel vulnerabilities USN-1006-1";
tag_affected = "webkit vulnerabilities on Ubuntu 9.10 ,
  Ubuntu 10.04 LTS";
tag_solution = "Please Install the Updated Packages.";


if(description)
{
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-1006-1/");
  script_oid("1.3.6.1.4.1.25623.1.0.313413");
  script_cve_id("CVE-2009-2797","CVE-2009-2841","CVE-2010-0046","CVE-2010-0047","CVE-2010-0048","CVE-2010-0049","CVE-2010-0050","CVE-2010-0051","CVE-2010-0052","CVE-2010-0053","CVE-2010-0054","CVE-2010-0314","CVE-2010-0647","CVE-2010-0650","CVE-2010-0651","CVE-2010-0656","CVE-2010-1386","CVE-2010-1387","CVE-2010-1389","CVE-2010-1390","CVE-2010-1391","CVE-2010-1392","CVE-2010-1393","CVE-2010-1394","CVE-2010-1395","CVE-2010-1396","CVE-2010-1397","CVE-2010-1398","CVE-2010-1400","CVE-2010-1401","CVE-2010-1402","CVE-2010-1403","CVE-2010-1404","CVE-2010-1405","CVE-2010-1406","CVE-2010-1407","CVE-2010-1408","CVE-2010-1409","CVE-2010-1410","CVE-2010-1412","CVE-2010-1414","CVE-2010-1415","CVE-2010-1416","CVE-2010-1417","CVE-2010-1418","CVE-2010-1419","CVE-2010-1421","CVE-2010-1422","CVE-2010-1664","CVE-2010-1665","CVE-2010-1758","CVE-2010-1759","CVE-2010-1760","CVE-2010-1761","CVE-2010-1762","CVE-2010-1764","CVE-2010-1766","CVE-2010-1767","CVE-2010-1770","CVE-2010-1771","CVE-2010-1772","CVE-2010-1773","CVE-2010-1774","CVE-2010-1780","CVE-2010-1781","CVE-2010-1782","CVE-2010-1783","CVE-2010-1784","CVE-2010-1785","CVE-2010-1786","CVE-2010-1787","CVE-2010-1788","CVE-2010-1790","CVE-2010-1792","CVE-2010-1793","CVE-2010-1807","CVE-2010-1812","CVE-2010-1814","CVE-2010-1815","CVE-2010-2264","CVE-2010-2647","CVE-2010-2648","CVE-2010-3113","CVE-2010-3114","CVE-2010-3115","CVE-2010-3116","CVE-2010-3248","CVE-2010-3257","CVE-2010-3259");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_version("$Revision: 8287 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-04 08:28:11 +0100 (Thu, 04 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-10-22 16:42:09 +0200 (Fri, 22 Oct 2010)");
  script_name("Ubuntu Update for webkit vulnerabilities USN-1006-1");

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

  if ((res = isdpkgvuln(pkg:"libwebkit-1.0-2-dbg", ver:"1.2.5-0ubuntu0.9.10.1", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libwebkit-1.0-2", ver:"1.2.5-0ubuntu0.9.10.1", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libwebkit-dev", ver:"1.2.5-0ubuntu0.9.10.1", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libwebkit-1.0-common", ver:"1.2.5-0ubuntu0.9.10.1", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU10.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"libwebkit-1.0-2-dbg", ver:"1.2.5-0ubuntu0.10.04.1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libwebkit-1.0-2", ver:"1.2.5-0ubuntu0.10.04.1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libwebkit-dev", ver:"1.2.5-0ubuntu0.10.04.1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"gir1.0-webkit-1.0", ver:"1.2.5-0ubuntu0.10.04.1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libwebkit-1.0-common", ver:"1.2.5-0ubuntu0.10.04.1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
