###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for rhn-client-tools RHSA-2010:0449-01
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
tag_insight = "Red Hat Network Client Tools provide programs and libraries that allow your
  system to receive software updates from the Red Hat Network (RHN).

  It was discovered that rhn-client-tools set insecure permissions on the
  loginAuth.pkl file, used to store session credentials for authenticating
  connections to Red Hat Network servers. A local, unprivileged user could
  use these credentials to download packages from the Red Hat Network. They
  could also manipulate package or action lists associated with the system's
  profile. (CVE-2010-1439)
  
  Users of rhn-client-tools are advised to upgrade to these updated packages,
  which contain a backported patch to correct this issue.";

tag_affected = "rhn-client-tools on Red Hat Enterprise Linux (v. 5 server)";
tag_solution = "Please Install the Updated Packages.";


if(description)
{
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/rhsa-announce/2010-June/msg00000.html");
  script_oid("1.3.6.1.4.1.25623.1.0.313967");
  script_version("$Revision: 8207 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-21 08:30:12 +0100 (Thu, 21 Dec 2017) $");
  script_tag(name:"creation_date", value:"2010-06-07 15:46:00 +0200 (Mon, 07 Jun 2010)");
  script_xref(name: "RHSA", value: "2010:0449-01");
  script_tag(name:"cvss_base", value:"3.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:N");
 script_cve_id("CVE-2010-1439");
  script_name("RedHat Update for rhn-client-tools RHSA-2010:0449-01");

  script_tag(name: "summary" , value: "Check for the Version of rhn-client-tools");
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

  if ((res = isrpmvuln(pkg:"rhn-check", rpm:"rhn-check~0.4.20~33.el5_5.2", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"rhn-client-tools", rpm:"rhn-client-tools~0.4.20~33.el5_5.2", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"rhn-setup", rpm:"rhn-setup~0.4.20~33.el5_5.2", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"rhn-setup-gnome", rpm:"rhn-setup-gnome~0.4.20~33.el5_5.2", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
