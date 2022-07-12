###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_998_1.nasl 8438 2018-01-16 17:38:23Z teissa $
#
# Ubuntu Update for thunderbird vulnerabilities USN-998-1
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
tag_insight = "Paul Nickerson, Jesse Ruderman, Olli Pettay, Igor Bukanov, Josh Soref, Gary
  Kwong, Martijn Wargers, Siddharth Agarwal and Michal Zalewski discovered
  various flaws in the browser engine. An attacker could exploit this to
  crash Thunderbird or possibly run arbitrary code as the user invoking the
  program. (CVE-2010-3175, CVE-2010-3176)

  Alexander Miller, Sergey Glazunov, and others discovered several flaws in
  the JavaScript engine. If JavaScript were enabled, an attacker could
  exploit this to crash Thunderbird or possibly run arbitrary code as the
  user invoking the program. (CVE-2010-3179, CVE-2010-3180, CVE-2010-3183)
  
  Eduardo Vela Nava discovered that Thunderbird could be made to violate the
  same-origin policy by using modal calls with JavaScript. If JavaScript were
  enabled, an attacker could exploit this to steal information from another
  site. (CVE-2010-3178)
  
  Dmitri GribenkoDmitri Gribenko discovered that Thunderbird did not properly
  setup the LD_LIBRARY_PATH environment variable. A local attacker could
  exploit this to execute arbitrary code as the user invoking the program.
  (CVE-2010-3182)";

tag_summary = "Ubuntu Update for Linux kernel vulnerabilities USN-998-1";
tag_affected = "thunderbird vulnerabilities on Ubuntu 10.04 LTS";
tag_solution = "Please Install the Updated Packages.";


if(description)
{
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-998-1/");
  script_oid("1.3.6.1.4.1.25623.1.0.314175");
  script_version("$Revision: 8438 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-16 18:38:23 +0100 (Tue, 16 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-10-22 16:42:09 +0200 (Fri, 22 Oct 2010)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2010-3175", "CVE-2010-3176", "CVE-2010-3178", "CVE-2010-3179", "CVE-2010-3180", "CVE-2010-3182", "CVE-2010-3183");
  script_name("Ubuntu Update for thunderbird vulnerabilities USN-998-1");

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

if(release == "UBUNTU10.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"thunderbird-dbg", ver:"3.0.9+build1+nobinonly-0ubuntu0.10.04.1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"thunderbird-dev", ver:"3.0.9+build1+nobinonly-0ubuntu0.10.04.1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"thunderbird-gnome-support-dbg", ver:"3.0.9+build1+nobinonly-0ubuntu0.10.04.1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"thunderbird-gnome-support", ver:"3.0.9+build1+nobinonly-0ubuntu0.10.04.1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"thunderbird", ver:"3.0.9+build1+nobinonly-0ubuntu0.10.04.1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
