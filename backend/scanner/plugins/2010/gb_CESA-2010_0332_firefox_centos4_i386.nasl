###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for firefox CESA-2010:0332 centos4 i386
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
tag_insight = "Mozilla Firefox is an open source Web browser. XULRunner provides the XUL
  Runtime environment for Mozilla Firefox.

  Several use-after-free flaws were found in Firefox. Visiting a web page
  containing malicious content could result in Firefox executing arbitrary
  code with the privileges of the user running Firefox. (CVE-2010-0175,
  CVE-2010-0176, CVE-2010-0177)
  
  A flaw was found in Firefox that could allow an applet to generate a drag
  and drop action from a mouse click. Such an action could be used to execute
  arbitrary JavaScript with the privileges of the user running Firefox.
  (CVE-2010-0178)
  
  A privilege escalation flaw was found in Firefox when the Firebug add-on is
  in use. The XMLHttpRequestSpy module in the Firebug add-on exposes a Chrome
  privilege escalation flaw that could be used to execute arbitrary
  JavaScript with the privileges of the user running Firefox. (CVE-2010-0179)
  
  Several flaws were found in the processing of malformed web content. A web
  page containing malicious content could cause Firefox to crash or,
  potentially, execute arbitrary code with the privileges of the user running
  Firefox. (CVE-2010-0174)
  
  For technical details regarding these flaws, refer to the Mozilla security
  advisories for Firefox 3.0.19. You can find a link to the Mozilla
  advisories in the References section of this erratum.
  
  All Firefox users should upgrade to these updated packages, which contain
  Firefox version 3.0.19, which corrects these issues. After installing the
  update, Firefox must be restarted for the changes to take effect.";
tag_solution = "Please Install the Updated Packages.";

tag_affected = "firefox on CentOS 4";


if(description)
{
  script_xref(name : "URL" , value : "http://lists.centos.org/pipermail/centos-announce/2010-April/016623.html");
  script_oid("1.3.6.1.4.1.25623.1.0.314335");
  script_version("$Revision: 8495 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-23 08:57:49 +0100 (Tue, 23 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-04-09 11:11:25 +0200 (Fri, 09 Apr 2010)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2010-0174", "CVE-2010-0175", "CVE-2010-0176", "CVE-2010-0177", "CVE-2010-0178", "CVE-2010-0179");
  script_name("CentOS Update for firefox CESA-2010:0332 centos4 i386");

  script_tag(name: "summary" , value: "Check for the Version of firefox");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms");
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
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

  if ((res = isrpmvuln(pkg:"firefox", rpm:"firefox~3.0.19~1.el4.centos", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
