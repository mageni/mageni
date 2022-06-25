###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for firefox CESA-2008:0549 centos3 i386
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
tag_insight = "Mozilla Firefox is an open source Web browser.

  Multiple flaws were found in the processing of malformed JavaScript
  content. A web page containing such malicious content could cause Firefox
  to crash or, potentially, execute arbitrary code as the user running
  Firefox. (CVE-2008-2801, CVE-2008-2802, CVE-2008-2803)
  
  Several flaws were found in the processing of malformed web content. A web
  page containing malicious content could cause Firefox to crash or,
  potentially, execute arbitrary code as the user running Firefox.
  (CVE-2008-2798, CVE-2008-2799, CVE-2008-2811)
  
  Several flaws were found in the way malformed web content was displayed. A
  web page containing specially-crafted content could potentially trick a
  Firefox user into surrendering sensitive information. (CVE-2008-2800)
  
  Two local file disclosure flaws were found in Firefox. A web page
  containing malicious content could cause Firefox to reveal the contents of
  a local file to a remote attacker. (CVE-2008-2805, CVE-2008-2810)
  
  A flaw was found in the way a malformed .properties file was processed by
  Firefox. A malicious extension could read uninitialized memory, possibly
  leaking sensitive data to the extension. (CVE-2008-2807)
  
  A flaw was found in the way Firefox escaped a listing of local file names.
  If a user could be tricked into listing a local directory containing
  malicious file names, arbitrary JavaScript could be run with the
  permissions of the user running Firefox. (CVE-2008-2808)
  
  A flaw was found in the way Firefox displayed information about self-signed
  certificates. It was possible for a self-signed certificate to contain
  multiple alternate name entries, which were not all displayed to the user,
  allowing them to mistakenly extend trust to an unknown site.
  (CVE-2008-2809)
  
  All Mozilla Firefox users should upgrade to this updated package, which
  contains backported patches that correct these issues.";

tag_affected = "firefox on CentOS 3";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.centos.org/pipermail/centos-announce/2008-July/015058.html");
  script_oid("1.3.6.1.4.1.25623.1.0.306821");
  script_version("$Revision: 6651 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-10 13:45:21 +0200 (Mon, 10 Jul 2017) $");
  script_tag(name:"creation_date", value:"2009-02-27 08:40:14 +0100 (Fri, 27 Feb 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-2798", "CVE-2008-2799", "CVE-2008-2800", "CVE-2008-2801", "CVE-2008-2802", "CVE-2008-2803", "CVE-2008-2805", "CVE-2008-2807", "CVE-2008-2808", "CVE-2008-2809", "CVE-2008-2810", "CVE-2008-2811");
  script_name( "CentOS Update for firefox CESA-2008:0549 centos3 i386");

  script_tag(name:"summary", value:"Check for the Version of firefox");
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

  if ((res = isrpmvuln(pkg:"firefox", rpm:"firefox~1.5.0.12~0.19.el4.centos3", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
