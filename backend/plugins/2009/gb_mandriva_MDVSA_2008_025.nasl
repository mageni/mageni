###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for x11-server-xgl MDVSA-2008:025 (x11-server-xgl)
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
tag_insight = "An input validation flaw was found in the X.org server's XFree86-Misc
  extension that could allow a malicious authorized client to cause
  a denial of service (crash), or potentially execute arbitrary code
  with root privileges on the X.org server (CVE-2007-5760).

  A flaw was found in the X.org server's XC-SECURITY extension that
  could allow a local user to verify the existence of an arbitrary file,
  even in directories that are not normally accessible to that user
  (CVE-2007-5958).
  
  A memory corruption flaw was found in the X.org server's XInput
  extension that could allow a malicious authorized client to cause a
  denial of service (crash) or potentially execute arbitrary code with
  root privileges on the X.org server (CVE-2007-6427).
  
  An information disclosure flaw was found in the X.org server's TOG-CUP
  extension that could allow a malicious authorized client to cause
  a denial of service (crash) or potentially view arbitrary memory
  content within the X.org server's address space (CVE-2007-6428).
  
  Two integer overflow flaws were found in the X.org server's EVI and
  MIT-SHM modules that could allow a malicious authorized client to
  cause a denial of service (crash) or potentially execute arbitrary
  code with the privileges of the X.org server (CVE-2007-6429).
  
  The updated packages have been patched to correct these issues.";

tag_affected = "x11-server-xgl on Mandriva Linux 2007.0,
  Mandriva Linux 2007.0/X86_64,
  Mandriva Linux 2007.1,
  Mandriva Linux 2007.1/X86_64,
  Mandriva Linux 2008.0,
  Mandriva Linux 2008.0/X86_64";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.mandriva.com/security-announce/2008-01/msg00039.php");
  script_oid("1.3.6.1.4.1.25623.1.0.305746");
  script_version("$Revision: 6568 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-06 15:04:21 +0200 (Thu, 06 Jul 2017) $");
  script_tag(name:"creation_date", value:"2009-04-09 14:26:37 +0200 (Thu, 09 Apr 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_xref(name: "MDVSA", value: "2008:025");
  script_cve_id("CVE-2007-5760", "CVE-2007-5958", "CVE-2007-6427", "CVE-2007-6428", "CVE-2007-6429");
  script_name( "Mandriva Update for x11-server-xgl MDVSA-2008:025 (x11-server-xgl)");

  script_tag(name:"summary", value:"Check for the Version of x11-server-xgl");
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

  if ((res = isrpmvuln(pkg:"x11-server-xgl", rpm:"x11-server-xgl~0.0.1~0.20070105.4.3mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "MNDK_2007.0")
{

  if ((res = isrpmvuln(pkg:"x11-server-xgl", rpm:"x11-server-xgl~0.0.1~0.20060714.11.3mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "MNDK_2008.0")
{

  if ((res = isrpmvuln(pkg:"x11-server-xgl", rpm:"x11-server-xgl~0.0.1~0.20070917.2.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
