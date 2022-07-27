###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_619_1.nasl 7969 2017-12-01 09:23:16Z santu $
#
# Ubuntu Update for firefox vulnerabilities USN-619-1
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
tag_insight = "Various flaws were discovered in the browser engine. By tricking
  a user into opening a malicious web page, an attacker could cause
  a denial of service via application crash, or possibly execute
  arbitrary code with the privileges of the user invoking the
  program. (CVE-2008-2798, CVE-2008-2799)

  Several problems were discovered in the JavaScript engine. If a
  user were tricked into opening a malicious web page, an attacker
  could perform cross-site scripting attacks. (CVE-2008-2800)
  
  Collin Jackson discovered various flaws in the JavaScript engine
  which allowed JavaScript to be injected into signed JAR files. If
  a user were tricked into opening malicious web content, an
  attacker may be able to execute arbitrary code with the privileges
  of a different website or link content within the JAR file to an
  attacker-controlled JavaScript file. (CVE-2008-2801)
  
  It was discovered that Firefox would allow non-privileged XUL
  documents to load chrome scripts from the fastload file. This
  could allow an attacker to execute arbitrary JavaScript code with
  chrome privileges. (CVE-2008-2802)
  
  A flaw was discovered in Firefox that allowed overwriting trusted
  objects via mozIJSSubScriptLoader.loadSubScript(). If a user were
  tricked into opening a malicious web page, an attacker could
  execute arbitrary code with the privileges of the user invoking the
  program. (CVE-2008-2803)
  
  Claudio Santambrogio discovered a vulnerability in Firefox which
  could lead to stealing of arbitrary files. If a user were tricked
  into opening malicious content, an attacker could force the browser
  into uploading local files to the remote server. (CVE-2008-2805)
  
  Gregory Fleischer discovered a flaw in Java LiveConnect. An attacker
  could exploit this to bypass the same-origin policy and create
  arbitrary socket connections to other domains. (CVE-2008-2806)
  
  Daniel Glazman found that an improperly encoded .properties file
  in an add-on can result in uninitialized memory being used. If
  a user were tricked into installing a malicious add-on, the
  browser may be able to see data from other programs.
  (CVE-2008-2807)
  
  Masahiro Yamada discovered that Firefox did not properly sanitize
  file URLs in directory listings, resulting in files from directory
  listings being opened in unintended ways or not being able to be
  opened by the browser at all. (CVE-2008-2808)
  
  John G. Myers discovered a weakness in the trust model used by
  Firefox regarding alternate names on self-signed certificates. If
  a user were tricked i ... 

  Description truncated, for more information please check the Reference URL";

tag_summary = "Ubuntu Update for Linux kernel vulnerabilities USN-619-1";
tag_affected = "firefox vulnerabilities on Ubuntu 6.06 LTS ,
  Ubuntu 7.04 ,
  Ubuntu 7.10";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-619-1/");
  script_oid("1.3.6.1.4.1.25623.1.0.308765");
  script_version("$Revision: 7969 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-01 10:23:16 +0100 (Fri, 01 Dec 2017) $");
  script_tag(name:"creation_date", value:"2009-03-23 10:59:50 +0100 (Mon, 23 Mar 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-2798", "CVE-2008-2799", "CVE-2008-2800", "CVE-2008-2801", "CVE-2008-2802", "CVE-2008-2803", "CVE-2008-2805", "CVE-2008-2806", "CVE-2008-2807", "CVE-2008-2808", "CVE-2008-2809", "CVE-2008-2810", "CVE-2008-2811");
  script_name( "Ubuntu Update for firefox vulnerabilities USN-619-1");

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

  if ((res = isdpkgvuln(pkg:"firefox-dbg", ver:"1.5.dfsg+1.5.0.15~prepatch080614c-0ubuntu1", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-dev", ver:"1.5.dfsg+1.5.0.15~prepatch080614c-0ubuntu1", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-gnome-support", ver:"1.5.dfsg+1.5.0.15~prepatch080614c-0ubuntu1", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox", ver:"1.5.dfsg+1.5.0.15~prepatch080614c-0ubuntu1", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libnspr-dev", ver:"1.firefox1.5.dfsg+1.5.0.15~prepatch080614c-0ubuntu1", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libnspr4", ver:"1.firefox1.5.dfsg+1.5.0.15~prepatch080614c-0ubuntu1", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libnss-dev", ver:"1.firefox1.5.dfsg+1.5.0.15~prepatch080614c-0ubuntu1", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libnss3", ver:"1.firefox1.5.dfsg+1.5.0.15~prepatch080614c-0ubuntu1", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-dom-inspector", ver:"1.5.dfsg+1.5.0.15~prepatch080614c-0ubuntu1", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"mozilla-firefox", ver:"1.5.dfsg+1.5.0.15~prepatch080614c-0ubuntu1", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"mozilla-firefox-dev", ver:"1.5.dfsg+1.5.0.15~prepatch080614c-0ubuntu1", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU7.04")
{

  if ((res = isdpkgvuln(pkg:"firefox-dbg", ver:"2.0.0.15+0nobinonly-0ubuntu0.7.4", rls:"UBUNTU7.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-dev", ver:"2.0.0.15+0nobinonly-0ubuntu0.7.4", rls:"UBUNTU7.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-gnome-support", ver:"2.0.0.15+0nobinonly-0ubuntu0.7.4", rls:"UBUNTU7.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-libthai", ver:"2.0.0.15+0nobinonly-0ubuntu0.7.4", rls:"UBUNTU7.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox", ver:"2.0.0.15+0nobinonly-0ubuntu0.7.4", rls:"UBUNTU7.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libnspr-dev", ver:"1.firefox2.0.0.15+0nobinonly-0ubuntu0.7.4", rls:"UBUNTU7.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libnspr4", ver:"1.firefox2.0.0.15+0nobinonly-0ubuntu0.7.4", rls:"UBUNTU7.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libnss-dev", ver:"1.firefox2.0.0.15+0nobinonly-0ubuntu0.7.4", rls:"UBUNTU7.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libnss3", ver:"1.firefox2.0.0.15+0nobinonly-0ubuntu0.7.4", rls:"UBUNTU7.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-dom-inspector", ver:"2.0.0.15+0nobinonly-0ubuntu0.7.4", rls:"UBUNTU7.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"mozilla-firefox-dev", ver:"2.0.0.15+0nobinonly-0ubuntu0.7.4", rls:"UBUNTU7.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"mozilla-firefox-dom-inspector", ver:"2.0.0.15+0nobinonly-0ubuntu0.7.4", rls:"UBUNTU7.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"mozilla-firefox-gnome-support", ver:"2.0.0.15+0nobinonly-0ubuntu0.7.4", rls:"UBUNTU7.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"mozilla-firefox", ver:"2.0.0.15+0nobinonly-0ubuntu0.7.4", rls:"UBUNTU7.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU7.10")
{

  if ((res = isdpkgvuln(pkg:"firefox-dbg", ver:"2.0.0.15+1nobinonly-0ubuntu0.7.10", rls:"UBUNTU7.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-dev", ver:"2.0.0.15+1nobinonly-0ubuntu0.7.10", rls:"UBUNTU7.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-gnome-support", ver:"2.0.0.15+1nobinonly-0ubuntu0.7.10", rls:"UBUNTU7.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-libthai", ver:"2.0.0.15+1nobinonly-0ubuntu0.7.10", rls:"UBUNTU7.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox", ver:"2.0.0.15+1nobinonly-0ubuntu0.7.10", rls:"UBUNTU7.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-dom-inspector", ver:"2.0.0.15+1nobinonly-0ubuntu0.7.10", rls:"UBUNTU7.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
