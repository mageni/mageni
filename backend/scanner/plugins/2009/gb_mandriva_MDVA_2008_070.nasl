###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for dkms MDVA-2008:070 (dkms)
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
tag_insight = "The dkms-minimal package in Mandriva Linux 2008 Spring did not require
  lsb-release. If lsb-release was not installed, the dkms modules were
  installed in the standard location, instead of the intended /dkms or
  /dkms-binary. This update fixes that issue.

  Due to another bug, dkms would consider older installed binary dkms
  modules as original modules when installing a newer version of the
  module as a source dkms package, thus wrongly moving the binary
  modules around. This update disables original_module handling, not
  needed anymore since the rework of dkms system in 2008 Spring.
  
  Dkms would also print an error message during an upgrade of binary
  module packages, and under certain conditions an additional warning
  message regarding multiple modules being found. This update removes
  those harmless messages when they are not appropriate.";

tag_affected = "dkms on Mandriva Linux 2008.1,
  Mandriva Linux 2008.1/X86_64";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.mandriva.com/security-announce/2008-05/msg00029.php");
  script_oid("1.3.6.1.4.1.25623.1.0.311516");
  script_version("$Revision: 6568 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-06 15:04:21 +0200 (Thu, 06 Jul 2017) $");
  script_tag(name:"creation_date", value:"2009-04-09 14:05:19 +0200 (Thu, 09 Apr 2009)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:N/A:N");
  script_xref(name: "MDVA", value: "2008:070");
  script_name( "Mandriva Update for dkms MDVA-2008:070 (dkms)");

  script_tag(name:"summary", value:"Check for the Version of dkms");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/release");
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

if(release == "MNDK_2008.1")
{

  if ((res = isrpmvuln(pkg:"dkms", rpm:"dkms~2.0.19~4.3mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"dkms-minimal", rpm:"dkms-minimal~2.0.19~4.3mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
