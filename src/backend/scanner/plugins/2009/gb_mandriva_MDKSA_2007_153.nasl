###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for gd MDKSA-2007:153 (gd)
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
tag_insight = "GD versions prior to 2.0.35 have a number of bugs which potentially
  lead to denial of service and possibly other issues.

  Integer overflow in gdImageCreateTrueColor function in the GD Graphics
  Library (libgd) before 2.0.35 allows user-assisted remote attackers
  to have unspecified remote attack vectors and impact. (CVE-2007-3472)
  
  The gdImageCreateXbm function in the GD Graphics Library (libgd)
  before 2.0.35 allows user-assisted remote attackers to cause a denial
  of service (crash) via unspecified vectors involving a gdImageCreate
  failure. (CVE-2007-3473)
  
  Multiple unspecified vulnerabilities in the GIF reader in the
  GD Graphics Library (libgd) before 2.0.35 allow user-assisted
  remote attackers to have unspecified attack vectors and
  impact. (CVE-2007-3474)
  
  The GD Graphics Library (libgd) before 2.0.35 allows user-assisted
  remote attackers to cause a denial of service (crash) via a GIF image
  that has no global color map. (CVE-2007-3475)
  
  Array index error in gd_gif_in.c in the GD Graphics Library (libgd)
  before 2.0.35 allows user-assisted remote attackers to cause
  a denial of service (crash and heap corruption) via large color
  index values in crafted image data, which results in a segmentation
  fault. (CVE-2007-3476)
  
  The (a) imagearc and (b) imagefilledarc functions in GD Graphics
  Library (libgd) before 2.0.35 allows attackers to cause a denial
  of service (CPU consumption) via a large (1) start or (2) end angle
  degree value. (CVE-2007-3477)
  
  Race condition in gdImageStringFTEx (gdft_draw_bitmap) in gdft.c in the
  GD Graphics Library (libgd) before 2.0.35 allows user-assisted remote
  attackers to cause a denial of service (crash) via unspecified vectors,
  possibly involving truetype font (TTF) support. (CVE-2007-3478)
  
  The security issues related to GIF image handling (CVE-2007-3473,
  CVE-2007-3474, CVE-2007-3475, CVE-2007-3476) do not affect Corporate
  3.0, as the version of GD included in these versions does not include
  GIF support.
  
  Updated packages have been patched to prevent these issues.";

tag_affected = "gd on Mandriva Linux 2007.0,
  Mandriva Linux 2007.0/X86_64,
  Mandriva Linux 2007.1,
  Mandriva Linux 2007.1/X86_64";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.mandriva.com/security-announce/2007-08/msg00002.php");
  script_oid("1.3.6.1.4.1.25623.1.0.311834");
  script_version("$Revision: 6568 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-06 15:04:21 +0200 (Thu, 06 Jul 2017) $");
  script_tag(name:"creation_date", value:"2009-04-09 13:57:01 +0200 (Thu, 09 Apr 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_xref(name: "MDKSA", value: "2007:153");
  script_cve_id("CVE-2007-3472", "CVE-2007-3473", "CVE-2007-3474", "CVE-2007-3475", "CVE-2007-3476", "CVE-2007-3477", "CVE-2007-3478");
  script_name( "Mandriva Update for gd MDKSA-2007:153 (gd)");

  script_tag(name:"summary", value:"Check for the Version of gd");
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

  if ((res = isrpmvuln(pkg:"gd-utils", rpm:"gd-utils~2.0.34~1.2mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgd2", rpm:"libgd2~2.0.34~1.2mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgd2-devel", rpm:"libgd2-devel~2.0.34~1.2mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgd2-static-devel", rpm:"libgd2-static-devel~2.0.34~1.2mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gd", rpm:"gd~2.0.34~1.2mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64gd2", rpm:"lib64gd2~2.0.34~1.2mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64gd2-devel", rpm:"lib64gd2-devel~2.0.34~1.2mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64gd2-static-devel", rpm:"lib64gd2-static-devel~2.0.34~1.2mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "MNDK_2007.0")
{

  if ((res = isrpmvuln(pkg:"gd-utils", rpm:"gd-utils~2.0.33~5.3mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgd2", rpm:"libgd2~2.0.33~5.3mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgd2-devel", rpm:"libgd2-devel~2.0.33~5.3mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgd2-static-devel", rpm:"libgd2-static-devel~2.0.33~5.3mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gd", rpm:"gd~2.0.33~5.3mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64gd2", rpm:"lib64gd2~2.0.33~5.3mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64gd2-devel", rpm:"lib64gd2-devel~2.0.33~5.3mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64gd2-static-devel", rpm:"lib64gd2-static-devel~2.0.33~5.3mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
