###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for tightvnc MDKSA-2007:080 (tightvnc)
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
tag_insight = "Local exploitation of a memory corruption vulnerability in the X.Org
  and XFree86 X server could allow an attacker to execute arbitrary code
  with privileges of the X server, typically root.

  The vulnerability exists in the ProcXCMiscGetXIDList() function in the
  XC-MISC extension. This request is used to determine what resource IDs
  are available for use. This function contains two vulnerabilities,
  both result in memory corruption of either the stack or heap. The
  ALLOCATE_LOCAL() macro used by this function allocates memory on the
  stack using alloca() on systems where alloca() is present, or using
  the heap otherwise. The handler function takes a user provided value,
  multiplies it, and then passes it to the above macro. This results in
  both an integer overflow vulnerability, and an alloca() stack pointer
  shifting vulnerability. Both can be exploited to execute arbitrary
  code. (CVE-2007-1003)
  
  iDefense reported two integer overflows in the way X.org handled
  various font files. A malicious local user could exploit these issues
  to potentially execute arbitrary code with the privileges of the X.org
  server. (CVE-2007-1351, CVE-2007-1352)
  
  TightVNC uses some of the same code base as Xorg, and has the same
  vulnerable code.
  
  Updated packages are patched to address these issues.";

tag_affected = "tightvnc on Mandriva Linux 2007.0,
  Mandriva Linux 2007.0/X86_64";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.mandriva.com/security-announce/2007-04/msg00008.php");
  script_oid("1.3.6.1.4.1.25623.1.0.311897");
  script_version("$Revision: 6568 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-06 15:04:21 +0200 (Thu, 06 Jul 2017) $");
  script_tag(name:"creation_date", value:"2009-04-09 13:53:01 +0200 (Thu, 09 Apr 2009)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_xref(name: "MDKSA", value: "2007:080");
  script_cve_id("CVE-2007-1003", "CVE-2007-1351", "CVE-2007-1352");
  script_name( "Mandriva Update for tightvnc MDKSA-2007:080 (tightvnc)");

  script_tag(name:"summary", value:"Check for the Version of tightvnc");
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

if(release == "MNDK_2007.0")
{

  if ((res = isrpmvuln(pkg:"tightvnc", rpm:"tightvnc~1.2.9~13.2mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tightvnc-doc", rpm:"tightvnc-doc~1.2.9~13.2mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tightvnc-server", rpm:"tightvnc-server~1.2.9~13.2mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
