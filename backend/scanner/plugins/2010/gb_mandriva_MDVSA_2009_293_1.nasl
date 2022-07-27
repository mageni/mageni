###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for squidGuard MDVSA-2009:293-1 (squidGuard)
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
tag_insight = "Multiple vulnerabilities has been found and corrected in squidGuard:

  Buffer overflow in sgLog.c in squidGuard 1.3 and 1.4 allows remote
  attackers to cause a denial of service (application hang or loss of
  blocking functionality) via a long URL with many / (slash) characters,
  related to emergency mode. (CVE-2009-3700).
  
  Multiple buffer overflows in squidGuard 1.4 allow remote attackers
  to bypass intended URL blocking via a long URL, related to (1)
  the relationship between a certain buffer size in squidGuard and a
  certain buffer size in Squid and (2) a redirect URL that contains
  information about the originally requested URL (CVE-2009-3826).
  
  squidGuard was upgraded to 1.2.1 for MNF2/CS3/CS4 with additional
  upstream security and bug fixes patches applied.
  
  This update fixes these vulnerabilities.
  
  Update:
  
  Packages for 2008.0 are provided for Corporate Desktop 2008.0
  customers.";

tag_affected = "squidGuard on Mandriva Linux 2008.0,
  Mandriva Linux 2008.0/X86_64";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.mandriva.com/security-announce/2010-01/msg00023.php");
  script_oid("1.3.6.1.4.1.25623.1.0.314953");
  script_version("$Revision: 8457 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-18 08:58:32 +0100 (Thu, 18 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-01-15 10:29:41 +0100 (Fri, 15 Jan 2010)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_xref(name: "MDVSA", value: "2009:293-1");
  script_cve_id("CVE-2009-3700", "CVE-2009-3826");
  script_name("Mandriva Update for squidGuard MDVSA-2009:293-1 (squidGuard)");

  script_tag(name: "summary" , value: "Check for the Version of squidGuard");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
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

if(release == "MNDK_2008.0")
{

  if ((res = isrpmvuln(pkg:"squidGuard", rpm:"squidGuard~1.2.0~14.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
