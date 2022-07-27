###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for clamav MDVSA-2008:189-1 (clamav)
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
tag_insight = "Multiple vulnerabilities were discovered in ClamAV and corrected with
  the 0.94 release, including:

  A vulnerability in ClamAV's chm-parser allowed remote attackers to
  cause a denial of service (application crash) via a malformed CHM file
  (CVE-2008-1389).
  
  A vulnerability in libclamav would allow attackers to cause a
  denial of service via vectors related to an out-of-memory condition
  (CVE-2008-3912).
  
  Multiple memory leaks were found in ClamAV that could possibly allow
  attackers to cause a denial of service via excessive memory consumption
  (CVE-2008-3913).
  
  A number of unspecified vulnerabilities in ClamAV were reported that
  have an unknown impact and attack vectors related to file descriptor
  leaks (CVE-2008-3914).
  
  Other bugs have also been corrected in 0.94 which is being provided
  with this update.  Because this new version has increased the major
  of the libclamav library, updated dependent packages are also being
  provided.
  
  Update:
  
  The previous update had experimental support enabled, which caused
  ClamAV to report the version as 0.94-exp rather than 0.94, causing
  ClamAV to produce bogus warnings about the installation being outdated.
  This update corrects that problem.";

tag_affected = "clamav on Mandriva Linux 2007.1,
  Mandriva Linux 2007.1/X86_64,
  Mandriva Linux 2008.0,
  Mandriva Linux 2008.0/X86_64,
  Mandriva Linux 2008.1,
  Mandriva Linux 2008.1/X86_64";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.mandriva.com/security-announce/2008-09/msg00028.php");
  script_oid("1.3.6.1.4.1.25623.1.0.308210");
  script_version("$Revision: 6568 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-06 15:04:21 +0200 (Thu, 06 Jul 2017) $");
  script_tag(name:"creation_date", value:"2009-04-09 14:18:58 +0200 (Thu, 09 Apr 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_xref(name: "MDVSA", value: "2008:189-1");
  script_cve_id("CVE-2008-1389", "CVE-2008-3912", "CVE-2008-3913", "CVE-2008-3914");
  script_name( "Mandriva Update for clamav MDVSA-2008:189-1 (clamav)");

  script_tag(name:"summary", value:"Check for the Version of clamav");
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

  if ((res = isrpmvuln(pkg:"clamav", rpm:"clamav~0.94~1.2mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"clamav-db", rpm:"clamav-db~0.94~1.2mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"clamav-milter", rpm:"clamav-milter~0.94~1.2mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"clamd", rpm:"clamd~0.94~1.2mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libclamav5", rpm:"libclamav5~0.94~1.2mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libclamav-devel", rpm:"libclamav-devel~0.94~1.2mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64clamav5", rpm:"lib64clamav5~0.94~1.2mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64clamav-devel", rpm:"lib64clamav-devel~0.94~1.2mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "MNDK_2008.0")
{

  if ((res = isrpmvuln(pkg:"clamav", rpm:"clamav~0.94~1.2mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"clamav-db", rpm:"clamav-db~0.94~1.2mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"clamav-milter", rpm:"clamav-milter~0.94~1.2mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"clamd", rpm:"clamd~0.94~1.2mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libclamav5", rpm:"libclamav5~0.94~1.2mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libclamav-devel", rpm:"libclamav-devel~0.94~1.2mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64clamav5", rpm:"lib64clamav5~0.94~1.2mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64clamav-devel", rpm:"lib64clamav-devel~0.94~1.2mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "MNDK_2008.1")
{

  if ((res = isrpmvuln(pkg:"clamav", rpm:"clamav~0.94~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"clamav-db", rpm:"clamav-db~0.94~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"clamav-milter", rpm:"clamav-milter~0.94~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"clamd", rpm:"clamd~0.94~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libclamav5", rpm:"libclamav5~0.94~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libclamav-devel", rpm:"libclamav-devel~0.94~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64clamav5", rpm:"lib64clamav5~0.94~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64clamav-devel", rpm:"lib64clamav-devel~0.94~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
