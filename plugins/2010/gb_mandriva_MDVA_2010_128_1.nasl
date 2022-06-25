###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for epiphany MDVA-2010:128-1 (epiphany)
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
tag_insight = "It was discovered that epiphany stopped working correctly on Mandriva
  Linux 2009.0 and 2009.1 with latest xulrunner. This update addresses
  this problem.

  Packages for 2009.0 are provided due to the Extended Maintenance
  Program.
  
  Update:
  
  The packages for Mandriva Linux 2009.0 had the wrong release number
  which prevented an upgrade. The update packages addresses the problem.";
tag_solution = "Please Install the Updated Packages.";

tag_affected = "epiphany on Mandriva Linux 2009.0,
  Mandriva Linux 2009.0/X86_64";


if(description)
{
  script_xref(name : "URL" , value : "http://lists.mandriva.com/security-announce/2010-04/msg00039.php");
  script_oid("1.3.6.1.4.1.25623.1.0.315104");
  script_version("$Revision: 8447 $");
  script_cve_id("CVE-2010-2251");
  script_tag(name:"last_modification", value:"$Date: 2018-01-17 17:12:19 +0100 (Wed, 17 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-04-29 13:13:58 +0200 (Thu, 29 Apr 2010)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_xref(name: "MDVA", value: "2010:128-1");
  script_name("Mandriva Update for epiphany MDVA-2010:128-1 (epiphany)");

  script_tag(name: "summary" , value: "Check for the Version of epiphany");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
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

if(release == "MNDK_2009.0")
{

  if ((res = isrpmvuln(pkg:"epiphany", rpm:"epiphany~2.24.3~0.2mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"epiphany-devel", rpm:"epiphany-devel~2.24.3~0.2mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
