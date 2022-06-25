###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for rpmdrake MDVA-2008:131 (rpmdrake)
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
tag_affected = "rpmdrake on Mandriva Linux 2008.1,
  Mandriva Linux 2008.1/X86_64";
tag_insight = "This update fixes several minor issues in rpmdrake:
  - it fixes a crash due to bad timing with the X server (#41010)
  - it fix empty per importance lists of updates in rpmdrake (list
  of all updates was OK, MandrivaUpdate was OK) (#41331) (regression
  introduced in 3.95 on 2007-09-14)
  - it makes rpmdrake only warn once per session when media XML metadata
  are newer than synthesis: in that case rpmdrake complained for every
  unsyncrhonized package (#42737)
  - it fixes a crash when selecting all packages (#40025)
  - it fixes a rare crash when canceling (#41970)";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.mandriva.com/security-announce/2008-10/msg00004.php");
  script_oid("1.3.6.1.4.1.25623.1.0.312112");
  script_version("$Revision: 6568 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-06 15:04:21 +0200 (Thu, 06 Jul 2017) $");
  script_tag(name:"creation_date", value:"2009-04-09 14:09:08 +0200 (Thu, 09 Apr 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_xref(name: "MDVA", value: "2008:131");
  script_name( "Mandriva Update for rpmdrake MDVA-2008:131 (rpmdrake)");

  script_tag(name:"summary", value:"Check for the Version of rpmdrake");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/release");
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

if(release == "MNDK_2008.1")
{

  if ((res = isrpmvuln(pkg:"rpmdrake", rpm:"rpmdrake~4.9.13.5~1.1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
