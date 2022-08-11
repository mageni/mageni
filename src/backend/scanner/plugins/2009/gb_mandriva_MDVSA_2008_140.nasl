###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for ruby MDVSA-2008:140 (ruby)
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
tag_insight = "Multiple vulnerabilities have been found in the Ruby interpreter and
  in Webrick, the webserver bundled with Ruby.

  Directory traversal vulnerability in WEBrick in Ruby 1.9.0
  and earlier, when using NTFS or FAT filesystems, allows remote
  attackers to read arbitrary CGI files via a trailing (1) + (plus),
  (2) %2b (encoded plus), (3) . (dot), (4) %2e (encoded dot), or
  (5) %20 (encoded space) character in the URI, possibly related to
  the WEBrick::HTTPServlet::FileHandler and WEBrick::HTTPServer.new
  functionality and the :DocumentRoot option. (CVE-2008-1891)
  
  Multiple integer overflows in the rb_str_buf_append function in
  Ruby 1.8.4 and earlier, 1.8.5 before 1.8.5-p231, 1.8.6 before
  1.8.6-p230, 1.8.7 before 1.8.7-p22, and 1.9.0 before 1.9.0-2
  allow context-dependent attackers to execute arbitrary code or
  cause a denial of service via unknown vectors that trigger memory
  corruption. (CVE-2008-2662)
  
  Multiple integer overflows in the rb_ary_store function in Ruby
  1.8.4 and earlier, 1.8.5 before 1.8.5-p231, 1.8.6 before 1.8.6-p230,
  and 1.8.7 before 1.8.7-p22 allow context-dependent attackers to
  execute arbitrary code or cause a denial of service via unknown
  vectors. (CVE-2008-2663)
  
  The rb_str_format function in Ruby 1.8.4 and earlier, 1.8.5 before
  1.8.5-p231, 1.8.6 before 1.8.6-p230, 1.8.7 before 1.8.7-p22, and 1.9.0
  before 1.9.0-2 allows context-dependent attackers to trigger memory
  corruption via unspecified vectors related to alloca. (CVE-2008-2664)
  
  Integer overflow in the rb_ary_splice function in Ruby 1.8.4
  and earlier, 1.8.5 before 1.8.5-p231, 1.8.6 before 1.8.6-p230,
  and 1.8.7 before 1.8.7-p22 allows context-dependent attackers to
  trigger memory corruption via unspecified vectors, aka the REALLOC_N
  variant. (CVE-2008-2725)
  
  Integer overflow in the rb_ary_splice function in Ruby 1.8.4 and
  earlier, 1.8.5 before 1.8.5-p231, 1.8.6 before 1.8.6-p230, 1.8.7 before
  1.8.7-p22, and 1.9.0 before 1.9.0-2 allows context-dependent attackers
  to trigger memory corruption, aka the beg + rlen issue. (CVE-2008-2726)
  
  Integer overflow in the rb_ary_fill function in array.c in Ruby before
  revision 17756 allows context-dependent attackers to cause a denial
  of service (crash) or possibly have unspecified other impact via a
  call to the Array#fill method with a start (aka beg) argument greater
  than ARY_MAX_SIZE. (CVE-2008-2376)
  
  The updated packages have been patched to fix these issues.";

tag_affected = "ruby on Mandriva Linux 2008.1,
  Mandriva Linux 2008.1/X86_64";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.mandriva.com/security-announce/2008-07/msg00019.php");
  script_oid("1.3.6.1.4.1.25623.1.0.310618");
  script_version("$Revision: 6568 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-06 15:04:21 +0200 (Thu, 06 Jul 2017) $");
  script_tag(name:"creation_date", value:"2009-04-09 14:26:37 +0200 (Thu, 09 Apr 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_xref(name: "MDVSA", value: "2008:140");
  script_cve_id("CVE-2008-1891", "CVE-2008-2662", "CVE-2008-2663", "CVE-2008-2664", "CVE-2008-2725", "CVE-2008-2726", "CVE-2008-2376");
  script_name( "Mandriva Update for ruby MDVSA-2008:140 (ruby)");

  script_tag(name:"summary", value:"Check for the Version of ruby");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/release");
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

if(release == "MNDK_2008.1")
{

  if ((res = isrpmvuln(pkg:"ruby", rpm:"ruby~1.8.6~9p114.1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ruby-devel", rpm:"ruby-devel~1.8.6~9p114.1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ruby-doc", rpm:"ruby-doc~1.8.6~9p114.1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ruby-tk", rpm:"ruby-tk~1.8.6~9p114.1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
