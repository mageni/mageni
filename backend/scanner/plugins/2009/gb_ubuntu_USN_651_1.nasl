###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_651_1.nasl 7969 2017-12-01 09:23:16Z santu $
#
# Ubuntu Update for ruby1.8 vulnerabilities USN-651-1
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
tag_insight = "Akira Tagoh discovered a vulnerability in Ruby which lead to an integer
  overflow. If a user or automated system were tricked into running a
  malicious script, an attacker could cause a denial of service or
  possibly execute arbitrary code with the privileges of the user
  invoking the program. (CVE-2008-2376)

  Laurent Gaffie discovered that Ruby did not properly check for memory
  allocation failures. If a user or automated system were tricked into
  running a malicious script, an attacker could cause a denial of
  service. (CVE-2008-3443)
  
  Keita Yamaguchi discovered several safe level vulnerabilities in Ruby.
  An attacker could use this to bypass intended access restrictions.
  (CVE-2008-3655)
  
  Keita Yamaguchi discovered that WEBrick in Ruby did not properly
  validate paths ending with &quot;.&quot;. A remote attacker could send a crafted
  HTTP request and cause a denial of service. (CVE-2008-3656)
  
  Keita Yamaguchi discovered that the dl module in Ruby did not check
  the taintness of inputs. An attacker could exploit this vulnerability
  to bypass safe levels and execute dangerous functions. (CVE-2008-3657)
  
  Luka Treiber and Mitja Kolsek discovered that REXML in Ruby did not
  always use expansion limits when processing XML documents. If a user or
  automated system were tricked into open a crafted XML file, an attacker
  could cause a denial of service via CPU consumption. (CVE-2008-3790)
  
  Jan Lieskovsky discovered several flaws in the name resolver of Ruby. A
  remote attacker could exploit this to spoof DNS entries, which could
  lead to misdirected traffic. This is a different vulnerability from
  CVE-2008-1447. (CVE-2008-3790)";

tag_summary = "Ubuntu Update for Linux kernel vulnerabilities USN-651-1";
tag_affected = "ruby1.8 vulnerabilities on Ubuntu 6.06 LTS ,
  Ubuntu 7.04 ,
  Ubuntu 7.10 ,
  Ubuntu 8.04 LTS";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-651-1/");
  script_oid("1.3.6.1.4.1.25623.1.0.306863");
  script_version("$Revision: 7969 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-01 10:23:16 +0100 (Fri, 01 Dec 2017) $");
  script_tag(name:"creation_date", value:"2009-03-23 10:59:50 +0100 (Mon, 23 Mar 2009)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cve_id("CVE-2008-2376", "CVE-2008-3443", "CVE-2008-3655", "CVE-2008-3656", "CVE-2008-3657", "CVE-2008-3790", "CVE-2008-3905", "CVE-2008-1447");
  script_name( "Ubuntu Update for ruby1.8 vulnerabilities USN-651-1");

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

  if ((res = isdpkgvuln(pkg:"libruby1.8-dbg", ver:"1.8.4-1ubuntu1.6", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libruby1.8", ver:"1.8.4-1ubuntu1.6", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"ruby1.8-dev", ver:"1.8.4-1ubuntu1.6", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"ruby1.8", ver:"1.8.4-1ubuntu1.6", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libdbm-ruby1.8", ver:"1.8.4-1ubuntu1.6", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libgdbm-ruby1.8", ver:"1.8.4-1ubuntu1.6", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libopenssl-ruby1.8", ver:"1.8.4-1ubuntu1.6", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libreadline-ruby1.8", ver:"1.8.4-1ubuntu1.6", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libtcltk-ruby1.8", ver:"1.8.4-1ubuntu1.6", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"irb1.8", ver:"1.8.4-1ubuntu1.6", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"rdoc1.8", ver:"1.8.4-1ubuntu1.6", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"ri1.8", ver:"1.8.4-1ubuntu1.6", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"ruby1.8-elisp", ver:"1.8.4-1ubuntu1.6", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"ruby1.8-examples", ver:"1.8.4-1ubuntu1.6", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU7.04")
{

  if ((res = isdpkgvuln(pkg:"libruby1.8-dbg", ver:"1.8.5-4ubuntu2.3", rls:"UBUNTU7.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libruby1.8", ver:"1.8.5-4ubuntu2.3", rls:"UBUNTU7.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"ruby1.8-dev", ver:"1.8.5-4ubuntu2.3", rls:"UBUNTU7.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"ruby1.8", ver:"1.8.5-4ubuntu2.3", rls:"UBUNTU7.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libdbm-ruby1.8", ver:"1.8.5-4ubuntu2.3", rls:"UBUNTU7.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libgdbm-ruby1.8", ver:"1.8.5-4ubuntu2.3", rls:"UBUNTU7.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libopenssl-ruby1.8", ver:"1.8.5-4ubuntu2.3", rls:"UBUNTU7.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libreadline-ruby1.8", ver:"1.8.5-4ubuntu2.3", rls:"UBUNTU7.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libtcltk-ruby1.8", ver:"1.8.5-4ubuntu2.3", rls:"UBUNTU7.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"irb1.8", ver:"1.8.5-4ubuntu2.3", rls:"UBUNTU7.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"rdoc1.8", ver:"1.8.5-4ubuntu2.3", rls:"UBUNTU7.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"ri1.8", ver:"1.8.5-4ubuntu2.3", rls:"UBUNTU7.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"ruby1.8-elisp", ver:"1.8.5-4ubuntu2.3", rls:"UBUNTU7.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"ruby1.8-examples", ver:"1.8.5-4ubuntu2.3", rls:"UBUNTU7.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU8.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"libruby1.8-dbg", ver:"1.8.6.111-2ubuntu1.2", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libruby1.8", ver:"1.8.6.111-2ubuntu1.2", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"ruby1.8-dev", ver:"1.8.6.111-2ubuntu1.2", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"ruby1.8", ver:"1.8.6.111-2ubuntu1.2", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libdbm-ruby1.8", ver:"1.8.6.111-2ubuntu1.2", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libgdbm-ruby1.8", ver:"1.8.6.111-2ubuntu1.2", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libopenssl-ruby1.8", ver:"1.8.6.111-2ubuntu1.2", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libreadline-ruby1.8", ver:"1.8.6.111-2ubuntu1.2", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libtcltk-ruby1.8", ver:"1.8.6.111-2ubuntu1.2", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"irb1.8", ver:"1.8.6.111-2ubuntu1.2", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"rdoc1.8", ver:"1.8.6.111-2ubuntu1.2", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"ri1.8", ver:"1.8.6.111-2ubuntu1.2", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"ruby1.8-elisp", ver:"1.8.6.111-2ubuntu1.2", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"ruby1.8-examples", ver:"1.8.6.111-2ubuntu1.2", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU7.10")
{

  if ((res = isdpkgvuln(pkg:"libruby1.8-dbg", ver:"1.8.6.36-1ubuntu3.3", rls:"UBUNTU7.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libruby1.8", ver:"1.8.6.36-1ubuntu3.3", rls:"UBUNTU7.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"ruby1.8-dev", ver:"1.8.6.36-1ubuntu3.3", rls:"UBUNTU7.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"ruby1.8", ver:"1.8.6.36-1ubuntu3.3", rls:"UBUNTU7.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libdbm-ruby1.8", ver:"1.8.6.36-1ubuntu3.3", rls:"UBUNTU7.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libgdbm-ruby1.8", ver:"1.8.6.36-1ubuntu3.3", rls:"UBUNTU7.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libopenssl-ruby1.8", ver:"1.8.6.36-1ubuntu3.3", rls:"UBUNTU7.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libreadline-ruby1.8", ver:"1.8.6.36-1ubuntu3.3", rls:"UBUNTU7.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libtcltk-ruby1.8", ver:"1.8.6.36-1ubuntu3.3", rls:"UBUNTU7.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"irb1.8", ver:"1.8.6.36-1ubuntu3.3", rls:"UBUNTU7.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"rdoc1.8", ver:"1.8.6.36-1ubuntu3.3", rls:"UBUNTU7.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"ri1.8", ver:"1.8.6.36-1ubuntu3.3", rls:"UBUNTU7.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"ruby1.8-elisp", ver:"1.8.6.36-1ubuntu3.3", rls:"UBUNTU7.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"ruby1.8-examples", ver:"1.8.6.36-1ubuntu3.3", rls:"UBUNTU7.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
