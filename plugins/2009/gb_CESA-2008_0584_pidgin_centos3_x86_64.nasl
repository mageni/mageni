###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for pidgin CESA-2008:0584 centos3 x86_64
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
tag_insight = "Pidgin is a multi-protocol Internet Messaging client.

  An integer overflow flaw was found in Pidgin's MSN protocol handler. If a
  user received a malicious MSN message, it was possible to execute arbitrary
  code with the permissions of the user running Pidgin. (CVE-2008-2927)
  
  Note: the default Pidgin privacy setting only allows messages from users in
  the buddy list. This prevents arbitrary MSN users from exploiting this
  flaw.
  
  This update also addresses the following bug:
  
  * when attempting to connect to the ICQ network, Pidgin would fail to
  connect, present an alert saying the &quot;The client version you are using is
  too old&quot;, and de-activate the ICQ account. This update restores Pidgin's
  ability to connect to the ICQ network.
  
  All Pidgin users should upgrade to these updated packages, which contain
  backported patches to resolve these issues.";

tag_affected = "pidgin on CentOS 3";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.centos.org/pipermail/centos-announce/2008-July/015086.html");
  script_oid("1.3.6.1.4.1.25623.1.0.309928");
  script_version("$Revision: 6651 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-10 13:45:21 +0200 (Mon, 10 Jul 2017) $");
  script_tag(name:"creation_date", value:"2009-02-27 08:40:14 +0100 (Fri, 27 Feb 2009)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2008-2927");
  script_name( "CentOS Update for pidgin CESA-2008:0584 centos3 x86_64");

  script_tag(name:"summary", value:"Check for the Version of pidgin");
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

  if ((res = isrpmvuln(pkg:"pidgin", rpm:"pidgin~1.5.1~2.el3", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
