###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for kdebase CESA-2010:0348 centos4 i386
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
tag_insight = "The K Desktop Environment (KDE) is a graphical desktop environment for the
  X Window System. The kdebase packages include core applications for KDE.

  A privilege escalation flaw was found in the KDE Display Manager (KDM). A
  local user with console access could trigger a race condition, possibly
  resulting in the permissions of an arbitrary file being set to world
  writable, allowing privilege escalation. (CVE-2010-0436)
  
  Red Hat would like to thank Sebastian Krahmer of the SuSE Security Team for
  responsibly reporting this issue.
  
  Users of KDE should upgrade to these updated packages, which contain a
  backported patch to correct this issue. The system should be rebooted for
  this update to take effect. After the reboot, administrators should
  manually remove all leftover user-owned dmctl-* directories in
  &quot;/var/run/xdmctl/&quot;.";
tag_solution = "Please Install the Updated Packages.";

tag_affected = "kdebase on CentOS 4";


if(description)
{
  script_xref(name : "URL" , value : "http://lists.centos.org/pipermail/centos-announce/2010-April/016625.html");
  script_oid("1.3.6.1.4.1.25623.1.0.314753");
  script_version("$Revision: 8457 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-18 08:58:32 +0100 (Thu, 18 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-04-29 13:13:58 +0200 (Thu, 29 Apr 2010)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2010-0436");
  script_name("CentOS Update for kdebase CESA-2010:0348 centos4 i386");

  script_tag(name: "summary" , value: "Check for the Version of kdebase");
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

  if ((res = isrpmvuln(pkg:"kdebase", rpm:"kdebase~3.3.1~13.el4_8.1", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kdebase-devel", rpm:"kdebase-devel~3.3.1~13.el4_8.1", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
