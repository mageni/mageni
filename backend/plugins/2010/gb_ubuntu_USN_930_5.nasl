###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_930_5.nasl 8438 2018-01-16 17:38:23Z teissa $
#
# Ubuntu Update for ant, apturl, Epiphany, gluezilla, gnome-python-extras, liferea, mozvoikko, OpenJDK, packagekit, ubufox, webfav, yelp update USN-930-5
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
tag_insight = "USN-930-4 fixed vulnerabilities in Firefox and Xulrunner on Ubuntu 9.04 and
  9.10. This update provides updated packages for use with Firefox 3.6 and
  Xulrunner 1.9.2.

  Original advisory details:
  
  If was discovered that Firefox could be made to access freed memory. If a
  user were tricked into viewing a malicious site, a remote attacker could
  cause a denial of service or possibly execute arbitrary code with the
  privileges of the user invoking the program. This issue only affected
  Ubuntu 8.04 LTS. (CVE-2010-1121)
  
  Several flaws were discovered in the browser engine of Firefox. If a
  user were tricked into viewing a malicious site, a remote attacker could
  cause a denial of service or possibly execute arbitrary code with the
  privileges of the user invoking the program. (CVE-2010-1200, CVE-2010-1201,
  CVE-2010-1202, CVE-2010-1203)
  
  A flaw was discovered in the way plugin instances interacted. An attacker
  could potentially exploit this and use one plugin to access freed memory from a
  second plugin to execute arbitrary code with the privileges of the user
  invoking the program. (CVE-2010-1198)
  
  An integer overflow was discovered in Firefox. If a user were tricked into
  viewing a malicious site, an attacker could overflow a buffer and cause a
  denial of service or possibly execute arbitrary code with the privileges of
  the user invoking the program. (CVE-2010-1196)
  
  Martin Barbella discovered an integer overflow in an XSLT node sorting
  routine. An attacker could exploit this to overflow a buffer and cause a
  denial of service or possibly execute arbitrary code with the privileges of
  the user invoking the program. (CVE-2010-1199)
  
  Michal Zalewski discovered that the focus behavior of Firefox could be
  subverted. If a user were tricked into viewing a malicious site, a remote
  attacker could use this to capture keystrokes. (CVE-2010-1125)
  
  Ilja van Sprundel discovered that the 'Content-Disposition: attachment'
  HTTP header was ignored when 'Content-Type: multipart' was also present.
  Under certain circumstances, this could potentially lead to cross-site
  scripting attacks. (CVE-2010-1197)
  
  Amit Klein discovered that Firefox did not seed its random number generator
  often enough. An attacker could exploit this to identify and track users
  across different web sites. (CVE-2008-5913)
  
  Several flaws were discovered in the browser engine of Firefox. If a user
  were tricked into viewing a malicious site,  ... 

  Description truncated, for more information please check the Reference URL";

tag_summary = "Ubuntu Update for Linux kernel vulnerabilities USN-930-5";
tag_affected = "ant, apturl, Epiphany, gluezilla, gnome-python-extras, liferea, mozvoikko,
  OpenJDK, packagekit, ubufox, webfav, yelp update on
  Ubuntu 9.04, Ubuntu 9.10";
tag_solution = "Please Install the Updated Packages.";


if(description)
{
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-930-5/");
  script_oid("1.3.6.1.4.1.25623.1.0.313591");
  script_version("$Revision: 8438 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-16 18:38:23 +0100 (Tue, 16 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-07-26 16:14:51 +0200 (Mon, 26 Jul 2010)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2010-1121", "CVE-2010-1200", "CVE-2010-1201", "CVE-2010-1202", "CVE-2010-1203", "CVE-2010-1198", "CVE-2010-1196", "CVE-2010-1199", "CVE-2010-1125", "CVE-2010-1197", "CVE-2008-5913", "CVE-2010-1208", "CVE-2010-1209", "CVE-2010-1211", "CVE-2010-1212", "CVE-2010-1214", "CVE-2010-1215", "CVE-2010-2752", "CVE-2010-2753", "CVE-2010-1205", "CVE-2010-1213", "CVE-2010-1207", "CVE-2010-1210", "CVE-2010-1206", "CVE-2010-2751", "CVE-2010-0654", "CVE-2010-2754");
  script_name("Ubuntu Update USN-930-5");

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

  if ((res = isdpkgvuln(pkg:"ant-gcj", ver:"1.7.1-4ubuntu0.2", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"ant-optional-gcj", ver:"1.7.1-4ubuntu0.2", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"python-eggtrayicon", ver:"2.25.3-3ubuntu1.9.10.1", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"python-gda", ver:"2.25.3-3ubuntu1.9.10.1", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"python-gdl", ver:"2.25.3-3ubuntu1.9.10.1", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"python-gksu2", ver:"2.25.3-3ubuntu1.9.10.1", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"python-gnome2-extras-dbg", ver:"2.25.3-3ubuntu1.9.10.1", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"python-gnome2-extras", ver:"2.25.3-3ubuntu1.9.10.1", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"python-gtkhtml2", ver:"2.25.3-3ubuntu1.9.10.1", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"python-gtkmozembed", ver:"2.25.3-3ubuntu1.9.10.1", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"python-gtkspell", ver:"2.25.3-3ubuntu1.9.10.1", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"mozvoikko", ver:"1.0-1ubuntu3.9.10.1", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"icedtea-6-jre-cacao", ver:"6b18-1.8-4ubuntu3~9.10.2", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"icedtea6-plugin", ver:"6b18-1.8-4ubuntu3~9.10.2", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-6-dbg", ver:"6b18-1.8-4ubuntu3~9.10.2", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-6-demo", ver:"6b18-1.8-4ubuntu3~9.10.2", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-6-jdk", ver:"6b18-1.8-4ubuntu3~9.10.2", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-6-jre-headless", ver:"6b18-1.8-4ubuntu3~9.10.2", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-6-jre", ver:"6b18-1.8-4ubuntu3~9.10.2", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"yelp", ver:"2.28.0-0ubuntu2.9.10.1", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-6-jre-zero", ver:"6b18-1.8-4ubuntu3~9.10.2", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"ant-doc", ver:"1.7.1-4ubuntu0.2", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"ant-optional", ver:"1.7.1-4ubuntu0.2", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"ant", ver:"1.7.1-4ubuntu0.2", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"python-gnome2-extras-dev", ver:"2.25.3-3ubuntu1.9.10.1", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-6-doc", ver:"6b18-1.8-4ubuntu3~9.10.2", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-6-jre-lib", ver:"6b18-1.8-4ubuntu3~9.10.2", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-6-source", ver:"6b18-1.8-4ubuntu3~9.10.2", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"ubufox", ver:"0.9~rc2-0ubuntu0.9.10.1", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"webfav", ver:"1.16-0ubuntu1.9.10.1", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU9.04")
{

  if ((res = isdpkgvuln(pkg:"ant-gcj", ver:"1.7.1-0ubuntu2.2", rls:"UBUNTU9.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"ant-optional-gcj", ver:"1.7.1-0ubuntu2.2", rls:"UBUNTU9.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"epiphany-browser-dbg", ver:"2.26.1-0ubuntu1.9.04.1", rls:"UBUNTU9.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"epiphany-gecko", ver:"2.26.1-0ubuntu1.9.04.1", rls:"UBUNTU9.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libgluezilla", ver:"2.0-1ubuntu1.9.04.1", rls:"UBUNTU9.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"python-gnome2-extras-dbg", ver:"2.19.1-0ubuntu14.9.04.1", rls:"UBUNTU9.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"python-gnome2-extras", ver:"2.19.1-0ubuntu14.9.04.1", rls:"UBUNTU9.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"python-gtkhtml2-dbg", ver:"2.19.1-0ubuntu14.9.04.1", rls:"UBUNTU9.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"python-gtkhtml2", ver:"2.19.1-0ubuntu14.9.04.1", rls:"UBUNTU9.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"liferea-dbg", ver:"1.4.26-0ubuntu1.9.04.1", rls:"UBUNTU9.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"liferea", ver:"1.4.26-0ubuntu1.9.04.1", rls:"UBUNTU9.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"mozvoikko", ver:"0.9.5-1ubuntu2.9.04.1", rls:"UBUNTU9.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"icedtea-6-jre-cacao", ver:"6b18-1.8-4ubuntu3~9.04.2", rls:"UBUNTU9.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"icedtea6-plugin", ver:"6b18-1.8-4ubuntu3~9.04.2", rls:"UBUNTU9.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-6-dbg", ver:"6b18-1.8-4ubuntu3~9.04.2", rls:"UBUNTU9.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-6-demo", ver:"6b18-1.8-4ubuntu3~9.04.2", rls:"UBUNTU9.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-6-jdk", ver:"6b18-1.8-4ubuntu3~9.04.2", rls:"UBUNTU9.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-6-jre-headless", ver:"6b18-1.8-4ubuntu3~9.04.2", rls:"UBUNTU9.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-6-jre", ver:"6b18-1.8-4ubuntu3~9.04.2", rls:"UBUNTU9.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libpackagekit-glib-dev", ver:"0.3.14-0ubuntu5.9.04.1", rls:"UBUNTU9.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libpackagekit-glib11", ver:"0.3.14-0ubuntu5.9.04.1", rls:"UBUNTU9.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libpackagekit-qt-dev", ver:"0.3.14-0ubuntu5.9.04.1", rls:"UBUNTU9.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libpackagekit-qt11", ver:"0.3.14-0ubuntu5.9.04.1", rls:"UBUNTU9.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"packagekit-backend-apt", ver:"0.3.14-0ubuntu5.9.04.1", rls:"UBUNTU9.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"packagekit", ver:"0.3.14-0ubuntu5.9.04.1", rls:"UBUNTU9.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"yelp", ver:"2.25.1-0ubuntu5.9.04.1", rls:"UBUNTU9.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-6-jre-zero", ver:"6b18-1.8-4ubuntu3~9.04.2", rls:"UBUNTU9.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"gstreamer0.10-packagekit", ver:"0.3.14-0ubuntu5.9.04.1", rls:"UBUNTU9.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"mozilla-packagekit", ver:"0.3.14-0ubuntu5.9.04.1", rls:"UBUNTU9.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"packagekit-backend-smart", ver:"0.3.14-0ubuntu5.9.04.1", rls:"UBUNTU9.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"packagekit-backend-yum", ver:"0.3.14-0ubuntu5.9.04.1", rls:"UBUNTU9.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"ant-doc", ver:"1.7.1-0ubuntu2.2", rls:"UBUNTU9.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"ant-optional", ver:"1.7.1-0ubuntu2.2", rls:"UBUNTU9.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"ant", ver:"1.7.1-0ubuntu2.2", rls:"UBUNTU9.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"apturl", ver:"0.3.3ubuntu1.2", rls:"UBUNTU9.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"epiphany-browser-data", ver:"2.26.1-0ubuntu1.9.04.1", rls:"UBUNTU9.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"epiphany-browser-dev", ver:"2.26.1-0ubuntu1.9.04.1", rls:"UBUNTU9.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"epiphany-browser", ver:"2.26.1-0ubuntu1.9.04.1", rls:"UBUNTU9.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"python-gnome2-extras-dev", ver:"2.19.1-0ubuntu14.9.04.1", rls:"UBUNTU9.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"python-gnome2-extras-doc", ver:"2.19.1-0ubuntu14.9.04.1", rls:"UBUNTU9.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-6-doc", ver:"6b18-1.8-4ubuntu3~9.04.2", rls:"UBUNTU9.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-6-jre-lib", ver:"6b18-1.8-4ubuntu3~9.04.2", rls:"UBUNTU9.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-6-source", ver:"6b18-1.8-4ubuntu3~9.04.2", rls:"UBUNTU9.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"python-packagekit", ver:"0.3.14-0ubuntu5.9.04.1", rls:"UBUNTU9.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"ubufox", ver:"0.9~rc2-0ubuntu0.9.04.2", rls:"UBUNTU9.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"webfav", ver:"1.11-0ubuntu1.9.04.1", rls:"UBUNTU9.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
