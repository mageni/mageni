###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for irb CESA-2008:0562 centos3 i386
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
tag_insight = "Ruby is an interpreted scripting language for quick and easy
  object-oriented programming.

  Multiple integer overflows leading to a heap overflow were discovered in
  the array- and string-handling code used by Ruby. An attacker could use
  these flaws to crash a Ruby application or, possibly, execute arbitrary
  code with the privileges of the Ruby application using untrusted inputs in
  array or string operations. (CVE-2008-2376, CVE-2008-2663, CVE-2008-2725,
  CVE-2008-2726)
  
  It was discovered that Ruby used the alloca() memory allocation function in
  the format (%) method of the String class without properly restricting
  maximum string length. An attacker could use this flaw to crash a Ruby
  application or, possibly, execute arbitrary code with the privileges of the
  Ruby application using long, untrusted strings as format strings.
  (CVE-2008-2664)
  
  Red Hat would like to thank Drew Yao of the Apple Product Security team for
  reporting these issues.
  
  A flaw was discovered in the way Ruby's CGI module handles certain HTTP
  requests. A remote attacker could send a specially crafted request and
  cause the Ruby CGI script to enter an infinite loop, possibly causing a
  denial of service. (CVE-2006-6303)
  
  Users of Ruby should upgrade to these updated packages, which contain a
  backported patches to resolve these issues.";

tag_affected = "irb on CentOS 3";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.centos.org/pipermail/centos-announce/2008-July/015124.html");
  script_oid("1.3.6.1.4.1.25623.1.0.308380");
  script_version("$Revision: 6651 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-10 13:45:21 +0200 (Mon, 10 Jul 2017) $");
  script_tag(name:"creation_date", value:"2009-02-27 08:40:14 +0100 (Fri, 27 Feb 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-2663", "CVE-2008-2664", "CVE-2008-2725", "CVE-2008-2726", "CVE-2006-6303", "CVE-2008-2376");
  script_name( "CentOS Update for irb CESA-2008:0562 centos3 i386");

  script_tag(name:"summary", value:"Check for the Version of irb");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms");
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");


res = "";
if(release == NULL){
  exit(0);
}

if(release == "CentOS3")
{

  if ((res = isrpmvuln(pkg:"irb", rpm:"irb~1.6.8~12.el3", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ruby", rpm:"ruby~1.6.8~12.el3", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ruby-devel", rpm:"ruby-devel~1.6.8~12.el3", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ruby-docs", rpm:"ruby-docs~1.6.8~12.el3", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ruby-libs", rpm:"ruby-libs~1.6.8~12.el3", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ruby-mode", rpm:"ruby-mode~1.6.8~12.el3", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ruby-tcltk", rpm:"ruby-tcltk~1.6.8~12.el3", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
