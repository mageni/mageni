###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for xen MDKSA-2007:203 (xen)
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
tag_insight = "Tavis Ormandy discovered a heap overflow flaw during video-to-video
  copy operations in the Cirrus VGA extension code that is used in Xen.
  A malicious local administrator of a guest domain could potentially
  trigger this flaw and execute arbitrary code outside of the domain
  (CVE-2007-1320).

  Tavis Ormandy also discovered insufficient input validation leading to
  a heap overflow in the NE2000 network driver in Xen.  If the driver
  is in use, a malicious local administrator of a guest domain could
  potentially trigger this flaw and execute arbitrary code outside of
  the domain (CVE-2007-1321, CVE-2007-5729, CVE-2007-5730).
  
  Steve Kemp found that xen-utils used insecure temporary files within
  the xenmon tool that could allow local users to truncate arbitrary
  files (CVE-2007-3919).
  
  Joris van Rantwijk discovered a flaw in Pygrub, which is used as a
  boot loader for guest domains.  A malicious local administrator of
  a guest domain could create a carefully-crafted grub.conf file which
  could trigger the execution of arbitrary code outside of that domain
  (CVE-2007-4993).
  
  Updated packages have been patched to prevent these issues.";

tag_affected = "xen on Mandriva Linux 2007.0,
  Mandriva Linux 2007.0/X86_64,
  Mandriva Linux 2007.1,
  Mandriva Linux 2007.1/X86_64";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.mandriva.com/security-announce/2007-11/msg00000.php");
  script_oid("1.3.6.1.4.1.25623.1.0.312030");
  script_version("$Revision: 6568 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-06 15:04:21 +0200 (Thu, 06 Jul 2017) $");
  script_tag(name:"creation_date", value:"2009-04-09 14:00:25 +0200 (Thu, 09 Apr 2009)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_xref(name: "MDKSA", value: "2007:203");
  script_cve_id("CVE-2007-1320", "CVE-2007-1321", "CVE-2007-5729", "CVE-2007-5730", "CVE-2007-3919", "CVE-2007-4993");
  script_name( "Mandriva Update for xen MDKSA-2007:203 (xen)");

  script_tag(name:"summary", value:"Check for the Version of xen");
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

if(release == "MNDK_2007.1")
{

  if ((res = isrpmvuln(pkg:"xen", rpm:"xen~3.0.3~0.20060703.5.1mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "MNDK_2007.0")
{

  if ((res = isrpmvuln(pkg:"xen", rpm:"xen~3.0.3~0.20060703.3.1mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
