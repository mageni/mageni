###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_645_2.nasl 7969 2017-12-01 09:23:16Z santu $
#
# Ubuntu Update for firefox vulnerabilities USN-645-2
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
tag_insight = "USN-645-1 fixed vulnerabilities in Firefox and xulrunner for Ubuntu
  7.04, 7.10 and 8.04 LTS. This provides the corresponding update for
  Ubuntu 6.06 LTS.

  Original advisory details:
  
  Justin Schuh, Tom Cross and Peter Williams discovered errors in the
  Firefox URL parsing routines. If a user were tricked into opening a
  crafted hyperlink, an attacker could overflow a stack buffer and
  execute arbitrary code. (CVE-2008-0016)
  
  It was discovered that the same-origin check in Firefox could be
  bypassed. If a user were tricked into opening a malicious website,
  an attacker may be able to execute JavaScript in the context of a
  different website. (CVE-2008-3835)
  
  Several problems were discovered in the JavaScript engine. This
  could allow an attacker to execute scripts from page content with
  chrome privileges. (CVE-2008-3836)
  
  Paul Nickerson discovered Firefox did not properly process mouse
  click events. If a user were tricked into opening a malicious web
  page, an attacker could move the content window, which could
  potentially be used to force a user to perform unintended drag and
  drop operations. (CVE-2008-3837)
  
  Several problems were discovered in the browser engine. This could
  allow an attacker to execute code with chrome privileges.
  (CVE-2008-4058, CVE-2008-4059, CVE-2008-4060)
  
  Drew Yao, David Maciejak and other Mozilla developers found several
  problems in the browser engine of Firefox. If a user were tricked
  into opening a malicious web page, an attacker could cause a denial
  of service or possibly execute arbitrary code with the privileges
  of the user invoking the program. (CVE-2008-4061, CVE-2008-4062,
  CVE-2008-4063, CVE-2008-4064)
  
  Dave Reed discovered a flaw in the JavaScript parsing code when
  processing certain BOM characters. An attacker could exploit this
  to bypass script filters and perform cross-site scripting attacks.
  (CVE-2008-4065)
  
  Gareth Heyes discovered a flaw in the HTML parser of Firefox. If a
  user were tricked into opening a malicious web page, an attacker
  could bypass script filtering and perform cross-site scripting
  attacks. (CVE-2008-4066)
  
  Boris Zbarsky and Georgi Guninski independently discovered flaws in
  the resource: protocol. An attacker could exploit this to perform
  directory traversal, read information about the system, and prompt
  the user to save information in a file. (CVE-2008-4067,
  CVE-2008-4068)
  
  Billy Hoffman discovered a problem in the XBM decoder. If a user were
  tricked into opening a malicious web page or XBM file, an attacker
  may be able to cause a denial of service via application crash.
  (CVE-2008-4069)";

tag_summary = "Ubuntu Update for Linux kernel vulnerabilities USN-645-2";
tag_affected = "firefox vulnerabilities on Ubuntu 6.06 LTS";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-645-2/");
  script_oid("1.3.6.1.4.1.25623.1.0.310147");
  script_version("$Revision: 7969 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-01 10:23:16 +0100 (Fri, 01 Dec 2017) $");
  script_tag(name:"creation_date", value:"2009-03-23 10:59:50 +0100 (Mon, 23 Mar 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-0016", "CVE-2008-3835", "CVE-2008-3836", "CVE-2008-3837", "CVE-2008-4058", "CVE-2008-4059", "CVE-2008-4060", "CVE-2008-4061", "CVE-2008-4062", "CVE-2008-4063", "CVE-2008-4064", "CVE-2008-4065", "CVE-2008-4066", "CVE-2008-4067", "CVE-2008-4068", "CVE-2008-4069");
  script_name( "Ubuntu Update for firefox vulnerabilities USN-645-2");

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

if(release == "UBUNTU6.06 LTS")
{

  if ((res = isdpkgvuln(pkg:"firefox-dbg", ver:"1.5.dfsg+1.5.0.15~prepatch080614e-0ubuntu3", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-dev", ver:"1.5.dfsg+1.5.0.15~prepatch080614e-0ubuntu3", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-gnome-support", ver:"1.5.dfsg+1.5.0.15~prepatch080614e-0ubuntu3", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox", ver:"1.5.dfsg+1.5.0.15~prepatch080614e-0ubuntu3", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libnspr-dev", ver:"1.firefox1.5.dfsg+1.5.0.15~prepatch080614e-0ubuntu3", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libnspr4", ver:"1.firefox1.5.dfsg+1.5.0.15~prepatch080614e-0ubuntu3", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libnss-dev", ver:"1.firefox1.5.dfsg+1.5.0.15~prepatch080614e-0ubuntu3", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libnss3", ver:"1.firefox1.5.dfsg+1.5.0.15~prepatch080614e-0ubuntu3", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-dom-inspector", ver:"1.5.dfsg+1.5.0.15~prepatch080614e-0ubuntu3", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"mozilla-firefox", ver:"1.5.dfsg+1.5.0.15~prepatch080614e-0ubuntu3", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"mozilla-firefox-dev", ver:"1.5.dfsg+1.5.0.15~prepatch080614e-0ubuntu3", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
