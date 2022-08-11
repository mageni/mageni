###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for thunderbird CESA-2007:1083 centos4 i386
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

  A cross-site scripting flaw was found in the way Thunderbird handled the
  jar: URI scheme. It may be possible for a malicious HTML mail message to
  leverage this flaw, and conduct a cross-site scripting attack against a
  user running Thunderbird. (CVE-2007-5947)
  
  Several flaws were found in the way Thunderbird processed certain malformed
  HTML mail content. A HTML mail message containing malicious content could
  cause Thunderbird to crash, or potentially execute arbitrary code as the
  user running Thunderbird. (CVE-2007-5959)
  
  A race condition existed when Thunderbird set the &quot;window.location&quot;
  property when displaying HTML mail content. This flaw could allow a HTML
  mail message to set an arbitrary Referer header, which may lead to a
  Cross-site Request Forgery (CSRF) attack against websites that rely only on
  the Referer header for protection. (CVE-2007-5960) 
  
  All users of thunderbird are advised to upgrade to these updated packages,
  which contain backported patches to resolve these issues.";

tag_affected = "thunderbird on CentOS 4";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.centos.org/pipermail/centos-announce/2007-December/014547.html");
  script_oid("1.3.6.1.4.1.25623.1.0.306766");
  script_version("$Revision: 6651 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-10 13:45:21 +0200 (Mon, 10 Jul 2017) $");
  script_tag(name:"creation_date", value:"2009-02-27 08:31:09 +0100 (Fri, 27 Feb 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2007-5947", "CVE-2007-5959", "CVE-2007-5960");
  script_name( "CentOS Update for thunderbird CESA-2007:1083 centos4 i386");

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

  if ((res = isrpmvuln(pkg:"thunderbird", rpm:"thunderbird~1.5.0.12~7.el4.centos", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
