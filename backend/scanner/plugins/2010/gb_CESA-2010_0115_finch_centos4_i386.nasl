###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for finch CESA-2010:0115 centos4 i386
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
tag_insight = "Pidgin is an instant messaging program which can log in to multiple
  accounts on multiple instant messaging networks simultaneously.

  An input sanitization flaw was found in the way Pidgin's MSN protocol
  implementation handled MSNSLP invitations. A remote attacker could send a
  specially-crafted INVITE request that would cause a denial of service
  (memory corruption and Pidgin crash). (CVE-2010-0277)
  
  A denial of service flaw was found in Finch's XMPP chat implementation,
  when using multi-user chat. If a Finch user in a multi-user chat session
  were to change their nickname to contain the HTML &quot;br&quot; element, it would
  cause Finch to crash. (CVE-2010-0420)
  
  Red Hat would like to thank Sadrul Habib Chowdhury of the Pidgin project
  for responsibly reporting the CVE-2010-0420 issue.
  
  A denial of service flaw was found in the way Pidgin processed emoticon
  images. A remote attacker could flood the victim with emoticon images
  during mutual communication, leading to excessive CPU use. (CVE-2010-0423)
  
  These packages upgrade Pidgin to version 2.6.6. Refer to the Pidgin release
  notes for a full list of changes: <a  rel= &qt nofollow &qt  href= &qt http://developer.pidgin.im/wiki/ChangeLog &qt >http://developer.pidgin.im/wiki/ChangeLog</a>
  
  All Pidgin users are advised to upgrade to these updated packages, which
  correct these issues. Pidgin must be restarted for this update to take
  effect.";

tag_affected = "finch on CentOS 4";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.centos.org/pipermail/centos-announce/2010-February/016511.html");
  script_oid("1.3.6.1.4.1.25623.1.0.313233");
  script_version("$Revision: 8187 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-20 08:30:09 +0100 (Wed, 20 Dec 2017) $");
  script_tag(name:"creation_date", value:"2010-02-22 13:38:33 +0100 (Mon, 22 Feb 2010)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2010-0277", "CVE-2010-0420", "CVE-2010-0423");
  script_name("CentOS Update for finch CESA-2010:0115 centos4 i386");

  script_tag(name: "summary" , value: "Check for the Version of finch");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
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

  if ((res = isrpmvuln(pkg:"finch", rpm:"finch~2.6.6~1.el4", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"finch-devel", rpm:"finch-devel~2.6.6~1.el4", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpurple", rpm:"libpurple~2.6.6~1.el4", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpurple-devel", rpm:"libpurple-devel~2.6.6~1.el4", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpurple-perl", rpm:"libpurple-perl~2.6.6~1.el4", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpurple-tcl", rpm:"libpurple-tcl~2.6.6~1.el4", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pidgin", rpm:"pidgin~2.6.6~1.el4", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pidgin-devel", rpm:"pidgin-devel~2.6.6~1.el4", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pidgin-perl", rpm:"pidgin-perl~2.6.6~1.el4", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
