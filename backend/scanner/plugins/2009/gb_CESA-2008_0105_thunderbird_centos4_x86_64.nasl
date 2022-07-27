###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for thunderbird CESA-2008:0105 centos4 x86_64
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
tag_insight = "Mozilla Thunderbird is a standalone mail and newsgroup client.

  Several flaws were found in the way Thunderbird processed certain malformed
  HTML mail content. A HTML mail message containing malicious content could
  cause Thunderbird to crash, or potentially execute arbitrary code as the
  user running Thunderbird. (CVE-2008-0412, CVE-2008-0413, CVE-2008-0415,
  CVE-2008-0419)
  
  Several flaws were found in the way Thunderbird displayed malformed HTML
  mail content. A HTML mail message containing specially-crafted content
  could trick a user into surrendering sensitive information. (CVE-2008-0591,
  CVE-2008-0593)
  
  A flaw was found in the way Thunderbird handles certain chrome URLs. If a
  user has certain extensions installed, it could allow a malicious HTML mail
  message to steal sensitive session data. Note: this flaw does not affect a
  default installation of Thunderbird. (CVE-2008-0418)
  
  Note: JavaScript support is disabled by default in Thunderbird; the above
  issues are not exploitable unless JavaScript is enabled.
  
  A flaw was found in the way Thunderbird saves certain text files. If a
  remote site offers a file of type &quot;plain/text&quot;, rather than &quot;text/plain&quot;,
  Thunderbird will not show future &quot;text/plain&quot; content to the user, forcing
  them to save those files locally to view the content. (CVE-2008-0592) 
  
  Users of thunderbird are advised to upgrade to these updated packages,
  which contain backported patches to resolve these issues.";

tag_affected = "thunderbird on CentOS 4";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.centos.org/pipermail/centos-announce/2008-February/014666.html");
  script_oid("1.3.6.1.4.1.25623.1.0.304560");
  script_version("$Revision: 6651 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-10 13:45:21 +0200 (Mon, 10 Jul 2017) $");
  script_tag(name:"creation_date", value:"2009-02-27 08:36:45 +0100 (Fri, 27 Feb 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-0412", "CVE-2008-0413", "CVE-2008-0415", "CVE-2008-0418", "CVE-2008-0419", "CVE-2008-0591", "CVE-2008-0592", "CVE-2008-0593");
  script_name( "CentOS Update for thunderbird CESA-2008:0105 centos4 x86_64");

  script_tag(name:"summary", value:"Check for the Version of thunderbird");
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

  if ((res = isrpmvuln(pkg:"thunderbird", rpm:"thunderbird~1.5.0.12~8.el4.centos", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
