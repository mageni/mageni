###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for sudo RHSA-2010:0122-01
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
tag_insight = "The sudo (superuser do) utility allows system administrators to give
  certain users the ability to run commands as root.

  A privilege escalation flaw was found in the way sudo handled the sudoedit
  pseudo-command. If a local user were authorized by the sudoers file to use
  this pseudo-command, they could possibly leverage this flaw to execute
  arbitrary code with the privileges of the root user. (CVE-2010-0426)
  
  The sudo utility did not properly initialize supplementary groups when the
  &quot;runas_default&quot; option (in the sudoers file) was used. If a local user
  were authorized by the sudoers file to perform their sudo commands under
  the account specified with &quot;runas_default&quot;, they would receive the root
  user's supplementary groups instead of those of the intended target user,
  giving them unintended privileges. (CVE-2010-0427)
  
  Users of sudo should upgrade to this updated package, which contains
  backported patches to correct these issues.";

tag_affected = "sudo on Red Hat Enterprise Linux (v. 5 server)";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/rhsa-announce/2010-February/msg00017.html");
  script_oid("1.3.6.1.4.1.25623.1.0.314050");
  script_version("$Revision: 8510 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-24 08:57:42 +0100 (Wed, 24 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-03-02 08:46:47 +0100 (Tue, 02 Mar 2010)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_xref(name: "RHSA", value: "2010:0122-01");
  script_cve_id("CVE-2010-0426", "CVE-2010-0427");
  script_name("RedHat Update for sudo RHSA-2010:0122-01");

  script_tag(name: "summary" , value: "Check for the Version of sudo");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms");
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

if(release == "RHENT_5")
{

  if ((res = isrpmvuln(pkg:"sudo", rpm:"sudo~1.6.9p17~6.el5_4", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sudo-debuginfo", rpm:"sudo-debuginfo~1.6.9p17~6.el5_4", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
