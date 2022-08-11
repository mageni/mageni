###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_428_2.nasl 7969 2017-12-01 09:23:16Z santu $
#
# Ubuntu Update for firefox regression USN-428-2
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
tag_insight = "USN-428-1 fixed vulnerabilities in Firefox 1.5.  However, changes to
  library paths caused applications depending on libnss3 to fail to start
  up.  This update fixes the problem.

  We apologize for the inconvenience.
  
  Original advisory details:
  
  Several flaws have been found that could be used to perform Cross-site
  scripting attacks. A malicious web site could exploit these to modify
  the contents or steal confidential data (such as passwords) from other
  opened web pages. (CVE-2006-6077, CVE-2007-0780, CVE-2007-0800,
  CVE-2007-0981, CVE-2007-0995, CVE-2007-0996)
  
  The SSLv2 protocol support in the NSS library did not sufficiently
  check the validity of public keys presented with a SSL certificate. A
  malicious SSL web site using SSLv2 could potentially exploit this to
  execute arbitrary code with the user's privileges.  (CVE-2007-0008)
  
  The SSLv2 protocol support in the NSS library did not sufficiently
  verify the validity of client master keys presented in an SSL client
  certificate. A remote attacker could exploit this to execute arbitrary
  code in a server application that uses the NSS library.
  (CVE-2007-0009)
  
  Various flaws have been reported that could allow an attacker to
  execute arbitrary code with user privileges by tricking the user into
  opening a malicious web page. (CVE-2007-0775, CVE-2007-0776,
  CVE-2007-0777, CVE-2007-1092)
  
  Two web pages could collide in the disk cache with the result that
  depending on order loaded the end of the longer document could be
  appended to the shorter when the shorter one was reloaded from the
  cache. It is possible a determined hacker could construct a targeted
  attack to steal some sensitive data from a particular web page. The
  potential victim would have to be already logged into the targeted
  service (or be fooled into doing so) and then visit the malicious
  site. (CVE-2007-0778)
  
  David Eckel reported that browser UI elements--such as the host name
  and security indicators--could be spoofed by using custom cursor
  images and a specially crafted style sheet. (CVE-2007-0779)";

tag_summary = "Ubuntu Update for Linux kernel vulnerabilities USN-428-2";
tag_affected = "firefox regression on Ubuntu 6.06 LTS";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-428-2/");
  script_oid("1.3.6.1.4.1.25623.1.0.307255");
  script_version("$Revision: 7969 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-01 10:23:16 +0100 (Fri, 01 Dec 2017) $");
  script_tag(name:"creation_date", value:"2009-03-23 10:55:18 +0100 (Mon, 23 Mar 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2006-6077", "CVE-2007-0780", "CVE-2007-0800", "CVE-2007-0981", "CVE-2007-0995", "CVE-2007-0996", "CVE-2007-0008", "CVE-2007-0009", "CVE-2007-0775", "CVE-2007-0776", "CVE-2007-0777", "CVE-2007-1092", "CVE-2007-0778", "CVE-2007-0779");
  script_name( "Ubuntu Update for firefox regression USN-428-2");

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

  if ((res = isdpkgvuln(pkg:"firefox-dbg", ver:"1.5.dfsg+1.5.0.10-0ubuntu0.6.06.2", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-dev", ver:"1.5.dfsg+1.5.0.10-0ubuntu0.6.06.2", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-dom-inspector", ver:"1.5.dfsg+1.5.0.10-0ubuntu0.6.06.2", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-gnome-support", ver:"1.5.dfsg+1.5.0.10-0ubuntu0.6.06.2", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox", ver:"1.5.dfsg+1.5.0.10-0ubuntu0.6.06.2", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libnspr-dev", ver:"1.firefox1.5.dfsg+1.5.0.10-0ubuntu0.6.06.2", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libnspr4", ver:"1.firefox1.5.dfsg+1.5.0.10-0ubuntu0.6.06.2", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libnss-dev", ver:"1.firefox1.5.dfsg+1.5.0.10-0ubuntu0.6.06.2", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libnss3", ver:"1.firefox1.5.dfsg+1.5.0.10-0ubuntu0.6.06.2", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"mozilla-firefox-dev", ver:"1.5.dfsg+1.5.0.10-0ubuntu0.6.06.2", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"mozilla-firefox", ver:"1.5.dfsg+1.5.0.10-0ubuntu0.6.06.2", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
