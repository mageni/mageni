###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_647_1.nasl 7969 2017-12-01 09:23:16Z santu $
#
# Ubuntu Update for mozilla-thunderbird, thunderbird vulnerabilities USN-647-1
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
tag_insight = "It was discovered that the same-origin check in Thunderbird could
  be bypassed. If a user had JavaScript enabled and were tricked into
  opening a malicious website, an attacker may be able to execute
  JavaScript in the context of a different website. (CVE-2008-3835)

  Several problems were discovered in the browser engine of
  Thunderbird. If a user had JavaScript enabled, this could allow an
  attacker to execute code with chrome privileges. (CVE-2008-4058,
  CVE-2008-4059, CVE-2008-4060)
  
  Drew Yao, David Maciejak and other Mozilla developers found several
  problems in the browser engine of Thunderbird. If a user had
  JavaScript enabled and were tricked into opening a malicious web
  page, an attacker could cause a denial of service or possibly
  execute arbitrary code with the privileges of the user invoking the
  program. (CVE-2008-4061, CVE-2008-4062, CVE-2008-4063, CVE-2008-4064)
  
  Dave Reed discovered a flaw in the JavaScript parsing code when
  processing certain BOM characters. An attacker could exploit this
  to bypass script filters and perform cross-site scripting attacks
  if a user had JavaScript enabled. (CVE-2008-4065)
  
  Gareth Heyes discovered a flaw in the HTML parser of Thunderbird. If
  a user had JavaScript enabled and were tricked into opening a
  malicious web page, an attacker could bypass script filtering and
  perform cross-site scripting attacks. (CVE-2008-4066)
  
  Boris Zbarsky and Georgi Guninski independently discovered flaws in
  the resource: protocol. An attacker could exploit this to perform
  directory traversal, read information about the system, and prompt
  the user to save information in a file. (CVE-2008-4067,
  CVE-2008-4068)
  
  Georgi Guninski discovered that Thunderbird improperly handled
  cancelled newsgroup messages. If a user opened a crafted newsgroup
  message, an attacker could cause a buffer overrun and potentially
  execute arbitrary code with the privileges of the user invoking the
  program. (CVE-2008-4070)";

tag_summary = "Ubuntu Update for Linux kernel vulnerabilities USN-647-1";
tag_affected = "mozilla-thunderbird, thunderbird vulnerabilities on Ubuntu 6.06 LTS ,
  Ubuntu 7.04 ,
  Ubuntu 7.10 ,
  Ubuntu 8.04 LTS";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-647-1/");
  script_oid("1.3.6.1.4.1.25623.1.0.306931");
  script_version("$Revision: 7969 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-01 10:23:16 +0100 (Fri, 01 Dec 2017) $");
  script_tag(name:"creation_date", value:"2009-03-23 10:59:50 +0100 (Mon, 23 Mar 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-3835", "CVE-2008-4058", "CVE-2008-4059", "CVE-2008-4060", "CVE-2008-4061", "CVE-2008-4062", "CVE-2008-4063", "CVE-2008-4064", "CVE-2008-4065", "CVE-2008-4066", "CVE-2008-4067", "CVE-2008-4068", "CVE-2008-4070");
  script_name( "Ubuntu Update for mozilla-thunderbird, thunderbird vulnerabilities USN-647-1");

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

  if ((res = isdpkgvuln(pkg:"mozilla-thunderbird-dev", ver:"1.5.0.13+1.5.0.15~prepatch080614g-0ubuntu0.6.06.1", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"mozilla-thunderbird-inspector", ver:"1.5.0.13+1.5.0.15~prepatch080614g-0ubuntu0.6.06.1", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"mozilla-thunderbird-typeaheadfind", ver:"1.5.0.13+1.5.0.15~prepatch080614g-0ubuntu0.6.06.1", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"mozilla-thunderbird", ver:"1.5.0.13+1.5.0.15~prepatch080614g-0ubuntu0.6.06.1", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU7.04")
{

  if ((res = isdpkgvuln(pkg:"mozilla-thunderbird-dev", ver:"1.5.0.13+1.5.0.15~prepatch080614g-0ubuntu0.7.04.1", rls:"UBUNTU7.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"mozilla-thunderbird-inspector", ver:"1.5.0.13+1.5.0.15~prepatch080614g-0ubuntu0.7.04.1", rls:"UBUNTU7.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"mozilla-thunderbird-typeaheadfind", ver:"1.5.0.13+1.5.0.15~prepatch080614g-0ubuntu0.7.04.1", rls:"UBUNTU7.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"mozilla-thunderbird", ver:"1.5.0.13+1.5.0.15~prepatch080614g-0ubuntu0.7.04.1", rls:"UBUNTU7.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU8.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"thunderbird-dev", ver:"2.0.0.17+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"thunderbird-gnome-support", ver:"2.0.0.17+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"thunderbird", ver:"2.0.0.17+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"mozilla-thunderbird-dev", ver:"2.0.0.17+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"mozilla-thunderbird", ver:"2.0.0.17+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU7.10")
{

  if ((res = isdpkgvuln(pkg:"thunderbird-dev", ver:"2.0.0.17+nobinonly-0ubuntu0.7.10.1", rls:"UBUNTU7.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"thunderbird-gnome-support", ver:"2.0.0.17+nobinonly-0ubuntu0.7.10.1", rls:"UBUNTU7.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"thunderbird", ver:"2.0.0.17+nobinonly-0ubuntu0.7.10.1", rls:"UBUNTU7.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"mozilla-thunderbird-dev", ver:"2.0.0.17+nobinonly-0ubuntu0.7.10.1", rls:"UBUNTU7.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"mozilla-thunderbird", ver:"2.0.0.17+nobinonly-0ubuntu0.7.10.1", rls:"UBUNTU7.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
