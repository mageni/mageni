###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_690_2.nasl 7969 2017-12-01 09:23:16Z santu $
#
# Ubuntu Update for firefox vulnerabilities USN-690-2
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
tag_insight = "Several flaws were discovered in the browser engine. These problems could allow
  an attacker to crash the browser and possibly execute arbitrary code with user
  privileges. (CVE-2008-5500)

  Boris Zbarsky discovered that the same-origin check in Firefox could be
  bypassed by utilizing XBL-bindings. An attacker could exploit this to read data
  from other domains. (CVE-2008-5503)
  
  Several problems were discovered in the JavaScript engine. An attacker could
  exploit feed preview vulnerabilities to execute scripts from page content with
  chrome privileges. (CVE-2008-5504)
  
  Marius Schilder discovered that Firefox did not properly handle redirects to
  an outside domain when an XMLHttpRequest was made to a same-origin resource.
  It's possible that sensitive information could be revealed in the
  XMLHttpRequest response. (CVE-2008-5506)
  
  Chris Evans discovered that Firefox did not properly protect a user's data when
  accessing a same-domain Javascript URL that is redirected to an unparsable
  Javascript off-site resource. If a user were tricked into opening a malicious
  website, an attacker may be able to steal a limited amount of private data.
  (CVE-2008-5507)
  
  Chip Salzenberg, Justin Schuh, Tom Cross, and Peter William discovered Firefox
  did not properly parse URLs when processing certain control characters.
  (CVE-2008-5508)
  
  Kojima Hajime discovered that Firefox did not properly handle an escaped null
  character. An attacker may be able to exploit this flaw to bypass script
  sanitization. (CVE-2008-5510)
  
  Several flaws were discovered in the Javascript engine. If a user were tricked
  into opening a malicious website, an attacker could exploit this to execute
  arbitrary Javascript code within the context of another website or with chrome
  privileges. (CVE-2008-5511, CVE-2008-5512)
  
  Flaws were discovered in the session-restore feature of Firefox. If a user were
  tricked into opening a malicious website, an attacker could exploit this to
  perform cross-site scripting attacks or execute arbitrary Javascript code with
  chrome privileges. (CVE-2008-5513)";

tag_summary = "Ubuntu Update for Linux kernel vulnerabilities USN-690-2";
tag_affected = "firefox vulnerabilities on Ubuntu 7.10";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-690-2/");
  script_oid("1.3.6.1.4.1.25623.1.0.305141");
  script_version("$Revision: 7969 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-01 10:23:16 +0100 (Fri, 01 Dec 2017) $");
  script_tag(name:"creation_date", value:"2009-03-23 10:59:50 +0100 (Mon, 23 Mar 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-5500", "CVE-2008-5503", "CVE-2008-5504", "CVE-2008-5506", "CVE-2008-5507", "CVE-2008-5508", "CVE-2008-5510", "CVE-2008-5511", "CVE-2008-5512", "CVE-2008-5513");
  script_name( "Ubuntu Update for firefox vulnerabilities USN-690-2");

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

if(release == "UBUNTU7.10")
{

  if ((res = isdpkgvuln(pkg:"firefox-dbg", ver:"2.0.0.19+nobinonly1-0ubuntu0.7.10.1", rls:"UBUNTU7.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-dev", ver:"2.0.0.19+nobinonly1-0ubuntu0.7.10.1", rls:"UBUNTU7.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-gnome-support", ver:"2.0.0.19+nobinonly1-0ubuntu0.7.10.1", rls:"UBUNTU7.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-libthai", ver:"2.0.0.19+nobinonly1-0ubuntu0.7.10.1", rls:"UBUNTU7.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox", ver:"2.0.0.19+nobinonly1-0ubuntu0.7.10.1", rls:"UBUNTU7.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-dom-inspector", ver:"2.0.0.19+nobinonly1-0ubuntu0.7.10.1", rls:"UBUNTU7.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
