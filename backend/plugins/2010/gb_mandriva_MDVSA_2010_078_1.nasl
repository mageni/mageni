###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for sudo MDVSA-2010:078-1 (sudo)
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
tag_insight = "A vulnerability has been found and corrected in sudo:

  The command matching functionality in sudo 1.6.8 through 1.7.2p5 does
  not properly handle when a file in the current working directory has
  the same name as a pseudo-command in the sudoers file and the PATH
  contains an entry for ., which allows local users to execute arbitrary
  commands via a Trojan horse executable, as demonstrated using sudoedit,
  a different vulnerability than CVE-2010-0426 (CVE-2010-1163).
  
  Packages for 2008.0 are provided for Corporate Desktop 2008.0
  customers.
  
  The updated packages have been patched to correct this issue.
  
  Update:
  
  Packages for 2009.0 are provided due to the Extended Maintenance
  Program.";
tag_solution = "Please Install the Updated Packages.";

tag_affected = "sudo on Mandriva Linux 2009.0,
  Mandriva Linux 2009.0/X86_64";


if(description)
{
  script_xref(name : "URL" , value : "http://lists.mandriva.com/security-announce/2010-04/msg00052.php");
  script_oid("1.3.6.1.4.1.25623.1.0.315008");
  script_version("$Revision: 8495 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-23 08:57:49 +0100 (Tue, 23 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-04-30 14:39:22 +0200 (Fri, 30 Apr 2010)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_xref(name: "MDVSA", value: "2010:078-1");
  script_cve_id("CVE-2010-0426", "CVE-2010-1163");
  script_name("Mandriva Update for sudo MDVSA-2010:078-1 (sudo)");

  script_tag(name: "summary" , value: "Check for the Version of sudo");
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

  if ((res = isrpmvuln(pkg:"sudo", rpm:"sudo~1.6.9p17~1.4mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
