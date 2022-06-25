###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for irb CESA-2008:0897 centos4 i386
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

  The Ruby DNS resolver library, resolv.rb, used predictable transaction IDs
  and a fixed source port when sending DNS requests. A remote attacker could
  use this flaw to spoof a malicious reply to a DNS query. (CVE-2008-3905)
  
  Ruby's XML document parsing module (REXML) was prone to a denial of service
  attack via XML documents with large XML entity definitions recursion. A
  specially-crafted XML file could cause a Ruby application using the REXML
  module to use an excessive amount of CPU and memory. (CVE-2008-3790)
  
  An insufficient &quot;taintness&quot; check flaw was discovered in Ruby's DL module,
  which provides direct access to the C language functions. An attacker could
  use this flaw to bypass intended safe-level restrictions by calling
  external C functions with the arguments from an untrusted tainted inputs.
  (CVE-2008-3657)
  
  A denial of service flaw was discovered in WEBrick, Ruby's HTTP server
  toolkit. A remote attacker could send a specially-crafted HTTP request to a
  WEBrick server that would cause the server to use an excessive amount of
  CPU time. (CVE-2008-3656)
  
  A number of flaws were found in the safe-level restrictions in Ruby. It
  was possible for an attacker to create a carefully crafted malicious script
  that can allow the bypass of certain safe-level restrictions. (CVE-2008-3655)
  
  A denial of service flaw was found in Ruby's regular expression engine. If
  a Ruby script tried to process a large amount of data via a regular
  expression, it could cause Ruby to enter an infinite-loop and crash.
  (CVE-2008-3443)
  
  Users of ruby should upgrade to these updated packages, which contain
  backported patches to resolve these issues.";

tag_affected = "irb on CentOS 4";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.centos.org/pipermail/centos-announce/2008-October/015355.html");
  script_oid("1.3.6.1.4.1.25623.1.0.307863");
  script_version("$Revision: 6651 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-10 13:45:21 +0200 (Mon, 10 Jul 2017) $");
  script_tag(name:"creation_date", value:"2009-02-27 09:02:20 +0100 (Fri, 27 Feb 2009)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cve_id("CVE-2008-3443", "CVE-2008-3655", "CVE-2008-3656", "CVE-2008-3657", "CVE-2008-3790", "CVE-2008-3905");
  script_name( "CentOS Update for irb CESA-2008:0897 centos4 i386");

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

if(release == "CentOS4")
{

  if ((res = isrpmvuln(pkg:"irb", rpm:"irb~1.8.1~7.el4_7.1", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ruby", rpm:"ruby~1.8.1~7.el4_7.1", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ruby-devel", rpm:"ruby-devel~1.8.1~7.el4_7.1", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ruby-docs", rpm:"ruby-docs~1.8.1~7.el4_7.1", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ruby-libs", rpm:"ruby-libs~1.8.1~7.el4_7.1", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ruby-mode", rpm:"ruby-mode~1.8.1~7.el4_7.1", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ruby-tcltk", rpm:"ruby-tcltk~1.8.1~7.el4_7.1", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
