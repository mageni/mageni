###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_575_1.nasl 7969 2017-12-01 09:23:16Z santu $
#
# Ubuntu Update for apache2 vulnerabilities USN-575-1
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
tag_insight = "It was discovered that Apache did not sanitize the Expect header from
  an HTTP request when it is reflected back in an error message, which
  could result in browsers becoming vulnerable to cross-site scripting
  attacks when processing the output. With cross-site scripting
  vulnerabilities, if a user were tricked into viewing server output
  during a crafted server request, a remote attacker could exploit this
  to modify the contents, or steal confidential data (such as passwords),
  within the same domain. This was only vulnerable in Ubuntu 6.06.
  (CVE-2006-3918)

  It was discovered that when configured as a proxy server and using a
  threaded MPM, Apache did not properly sanitize its input. A remote
  attacker could send Apache crafted date headers and cause a denial of
  service via application crash. By default, mod_proxy is disabled in
  Ubuntu. (CVE-2007-3847)
  
  It was discovered that mod_autoindex did not force a character set,
  which could result in browsers becoming vulnerable to cross-site
  scripting attacks when processing the output. (CVE-2007-4465)
  
  It was discovered that mod_imap/mod_imagemap did not force a
  character set, which could result in browsers becoming vulnerable
  to cross-site scripting attacks when processing the output. By
  default, mod_imap/mod_imagemap is disabled in Ubuntu. (CVE-2007-5000)
  
  It was discovered that mod_status when status pages were available,
  allowed for cross-site scripting attacks. By default, mod_status is
  disabled in Ubuntu. (CVE-2007-6388)
  
  It was discovered that mod_proxy_balancer did not sanitize its input,
  which could result in browsers becoming vulnerable to cross-site
  scripting attacks when processing the output. By default,
  mod_proxy_balancer is disabled in Ubuntu. This was only vulnerable
  in Ubuntu 7.04 and 7.10. (CVE-2007-6421)
  
  It was discovered that mod_proxy_balancer could be made to
  dereference a NULL pointer. A remote attacker could send a crafted
  request and cause a denial of service via application crash. By
  default, mod_proxy_balancer is disabled in Ubuntu. This was only
  vulnerable in Ubuntu 7.04 and 7.10. (CVE-2007-6422)
  
  It was discovered that mod_proxy_ftp did not force a character set,
  which could result in browsers becoming vulnerable to cross-site
  scripting attacks when processing the output. By default,
  mod_proxy_ftp is disabled in Ubuntu. (CVE-2008-0005)";

tag_summary = "Ubuntu Update for Linux kernel vulnerabilities USN-575-1";
tag_affected = "apache2 vulnerabilities on Ubuntu 6.06 LTS ,
  Ubuntu 6.10 ,
  Ubuntu 7.04 ,
  Ubuntu 7.10";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-575-1/");
  script_oid("1.3.6.1.4.1.25623.1.0.304565");
  script_version("$Revision: 7969 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-01 10:23:16 +0100 (Fri, 01 Dec 2017) $");
  script_tag(name:"creation_date", value:"2009-03-23 10:59:50 +0100 (Mon, 23 Mar 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2006-3918", "CVE-2007-3847", "CVE-2007-4465", "CVE-2007-5000", "CVE-2007-6388", "CVE-2007-6421", "CVE-2007-6422", "CVE-2008-0005");
  script_name( "Ubuntu Update for apache2 vulnerabilities USN-575-1");

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

if(release == "UBUNTU7.04")
{

  if ((res = isdpkgvuln(pkg:"apache2-mpm-event", ver:"2.2.3-3.2ubuntu2.1", rls:"UBUNTU7.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"apache2-mpm-prefork", ver:"2.2.3-3.2ubuntu2.1", rls:"UBUNTU7.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"apache2-mpm-worker", ver:"2.2.3-3.2ubuntu2.1", rls:"UBUNTU7.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"apache2-prefork-dev", ver:"2.2.3-3.2ubuntu2.1", rls:"UBUNTU7.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"apache2-threaded-dev", ver:"2.2.3-3.2ubuntu2.1", rls:"UBUNTU7.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"apache2-utils", ver:"2.2.3-3.2ubuntu2.1", rls:"UBUNTU7.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"apache2.2-common", ver:"2.2.3-3.2ubuntu2.1", rls:"UBUNTU7.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"apache2-doc", ver:"2.2.3-3.2ubuntu2.1", rls:"UBUNTU7.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"apache2-mpm-perchild", ver:"2.2.3-3.2ubuntu2.1", rls:"UBUNTU7.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"apache2-src", ver:"2.2.3-3.2ubuntu2.1", rls:"UBUNTU7.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"apache2", ver:"2.2.3-3.2ubuntu2.1", rls:"UBUNTU7.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU6.06 LTS")
{

  if ((res = isdpkgvuln(pkg:"apache2-common", ver:"2.0.55-4ubuntu2.3", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"apache2-mpm-perchild", ver:"2.0.55-4ubuntu2.3", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"apache2-mpm-prefork", ver:"2.0.55-4ubuntu2.3", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"apache2-mpm-worker", ver:"2.0.55-4ubuntu2.3", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"apache2-prefork-dev", ver:"2.0.55-4ubuntu2.3", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"apache2-threaded-dev", ver:"2.0.55-4ubuntu2.3", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"apache2-utils", ver:"2.0.55-4ubuntu2.3", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"apache2", ver:"2.0.55-4ubuntu2.3", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libapr0-dev", ver:"2.0.55-4ubuntu2.3", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libapr0", ver:"2.0.55-4ubuntu2.3", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"apache2-doc", ver:"2.0.55-4ubuntu2.3", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU6.10")
{

  if ((res = isdpkgvuln(pkg:"apache2-common", ver:"2.0.55-4ubuntu4.2", rls:"UBUNTU6.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"apache2-mpm-perchild", ver:"2.0.55-4ubuntu4.2", rls:"UBUNTU6.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"apache2-mpm-prefork", ver:"2.0.55-4ubuntu4.2", rls:"UBUNTU6.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"apache2-mpm-worker", ver:"2.0.55-4ubuntu4.2", rls:"UBUNTU6.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"apache2-prefork-dev", ver:"2.0.55-4ubuntu4.2", rls:"UBUNTU6.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"apache2-threaded-dev", ver:"2.0.55-4ubuntu4.2", rls:"UBUNTU6.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"apache2-utils", ver:"2.0.55-4ubuntu4.2", rls:"UBUNTU6.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"apache2", ver:"2.0.55-4ubuntu4.2", rls:"UBUNTU6.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libapr0-dev", ver:"2.0.55-4ubuntu4.2", rls:"UBUNTU6.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libapr0", ver:"2.0.55-4ubuntu4.2", rls:"UBUNTU6.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"apache2-doc", ver:"2.0.55-4ubuntu4.2", rls:"UBUNTU6.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU7.10")
{

  if ((res = isdpkgvuln(pkg:"apache2-mpm-event", ver:"2.2.4-3ubuntu0.1", rls:"UBUNTU7.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"apache2-mpm-prefork", ver:"2.2.4-3ubuntu0.1", rls:"UBUNTU7.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"apache2-mpm-worker", ver:"2.2.4-3ubuntu0.1", rls:"UBUNTU7.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"apache2-prefork-dev", ver:"2.2.4-3ubuntu0.1", rls:"UBUNTU7.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"apache2-threaded-dev", ver:"2.2.4-3ubuntu0.1", rls:"UBUNTU7.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"apache2-utils", ver:"2.2.4-3ubuntu0.1", rls:"UBUNTU7.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"apache2.2-common", ver:"2.2.4-3ubuntu0.1", rls:"UBUNTU7.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"apache2-doc", ver:"2.2.4-3ubuntu0.1", rls:"UBUNTU7.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"apache2-mpm-perchild", ver:"2.2.4-3ubuntu0.1", rls:"UBUNTU7.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"apache2-src", ver:"2.2.4-3ubuntu0.1", rls:"UBUNTU7.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"apache2", ver:"2.2.4-3ubuntu0.1", rls:"UBUNTU7.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
