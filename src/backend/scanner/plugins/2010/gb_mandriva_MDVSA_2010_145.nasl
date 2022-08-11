###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for libtiff MDVSA-2010:145 (libtiff)
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
tag_insight = "Multiple vulnerabilities has been discovered and corrected in libtiff:

  The TIFFYCbCrtoRGB function in LibTIFF 3.9.0 and 3.9.2, as used in
  ImageMagick, does not properly handle invalid ReferenceBlackWhite
  values, which allows remote attackers to cause a denial of service
  (application crash) via a crafted TIFF image that triggers an array
  index error, related to downsampled OJPEG input. (CVE-2010-2595)

  Multiple integer overflows in the Fax3SetupState function in tif_fax3.c
  in the FAX3 decoder in LibTIFF before 3.9.3 allow remote attackers to
  execute arbitrary code or cause a denial of service (application crash)
  via a crafted TIFF file that triggers a heap-based buffer overflow
  (CVE-2010-1411).

  Integer overflow in the TIFFroundup macro in LibTIFF before 3.9.3
  allows remote attackers to cause a denial of service (application
  crash) or possibly execute arbitrary code via a crafted TIFF file
  that triggers a buffer overflow (CVE-2010-2065).

  The TIFFRGBAImageGet function in LibTIFF 3.9.0 allows remote attackers
  to cause a denial of service (out-of-bounds read and application crash)
  via a TIFF file with an invalid combination of SamplesPerPixel and
  Photometric values (CVE-2010-2483).

  The TIFFVStripSize function in tif_strip.c in LibTIFF 3.9.0 and 3.9.2
  makes incorrect calls to the TIFFGetField function, which allows
  remote attackers to cause a denial of service (application crash) via
  a crafted TIFF image, related to downsampled OJPEG input and possibly
  related to a compiler optimization that triggers a divide-by-zero error
  (CVE-2010-2597).

  The TIFFExtractData macro in LibTIFF before 3.9.4 does not properly
  handle unknown tag types in TIFF directory entries, which allows
  remote attackers to cause a denial of service (out-of-bounds read
  and application crash) via a crafted TIFF file (CVE-2010-248).

  Packages for 2008.0 and 2009.0 are provided as of the Extended
  Maintenance Program. Please visit this link to learn more:
  http://store.mandriva.com/product_info.php?cPath=149&amp;products_id=490

  The updated packages have been patched to correct these issues.";
tag_solution = "Please Install the Updated Packages.";

tag_affected = "libtiff on Mandriva Linux 2008.0,
  Mandriva Linux 2008.0/X86_64,
  Mandriva Linux 2009.0,
  Mandriva Linux 2009.0/X86_64,
  Mandriva Linux 2009.1,
  Mandriva Linux 2009.1/X86_64,
  Mandriva Enterprise Server 5,
  Mandriva Enterprise Server 5/X86_64";


if(description)
{
  script_xref(name : "URL" , value : "http://lists.mandriva.com/security-announce/2010-08/msg00001.php");
  script_oid("1.3.6.1.4.1.25623.1.0.314014");
  script_version("$Revision: 8187 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-20 08:30:09 +0100 (Wed, 20 Dec 2017) $");
  script_tag(name:"creation_date", value:"2010-08-09 14:43:21 +0200 (Mon, 09 Aug 2010)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_xref(name: "MDVSA", value: "2010:145");
  script_cve_id("CVE-2010-2595", "CVE-2010-1411", "CVE-2010-2065", "CVE-2010-2483", "CVE-2010-2597", "CVE-2010-2481");
  script_name("Mandriva Update for libtiff MDVSA-2010:145 (libtiff)");

  script_tag(name: "summary" , value: "Check for the Version of libtiff");
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

if(release == "MNDK_2008.0")
{

  if ((res = isrpmvuln(pkg:"libtiff3", rpm:"libtiff3~3.8.2~8.3mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libtiff3-devel", rpm:"libtiff3-devel~3.8.2~8.3mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libtiff3-static-devel", rpm:"libtiff3-static-devel~3.8.2~8.3mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libtiff-progs", rpm:"libtiff-progs~3.8.2~8.3mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libtiff", rpm:"libtiff~3.8.2~8.3mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64tiff3", rpm:"lib64tiff3~3.8.2~8.3mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64tiff3-devel", rpm:"lib64tiff3-devel~3.8.2~8.3mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64tiff3-static-devel", rpm:"lib64tiff3-static-devel~3.8.2~8.3mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "MNDK_mes5")
{

  if ((res = isrpmvuln(pkg:"libtiff3", rpm:"libtiff3~3.8.2~12.3mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libtiff3-devel", rpm:"libtiff3-devel~3.8.2~12.3mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libtiff3-static-devel", rpm:"libtiff3-static-devel~3.8.2~12.3mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libtiff-progs", rpm:"libtiff-progs~3.8.2~12.3mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libtiff", rpm:"libtiff~3.8.2~12.3mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64tiff3", rpm:"lib64tiff3~3.8.2~12.3mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64tiff3-devel", rpm:"lib64tiff3-devel~3.8.2~12.3mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64tiff3-static-devel", rpm:"lib64tiff3-static-devel~3.8.2~12.3mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "MNDK_2009.1")
{

  if ((res = isrpmvuln(pkg:"libtiff3", rpm:"libtiff3~3.8.2~13.2mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libtiff3-devel", rpm:"libtiff3-devel~3.8.2~13.2mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libtiff3-static-devel", rpm:"libtiff3-static-devel~3.8.2~13.2mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libtiff-progs", rpm:"libtiff-progs~3.8.2~13.2mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libtiff", rpm:"libtiff~3.8.2~13.2mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64tiff3", rpm:"lib64tiff3~3.8.2~13.2mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64tiff3-devel", rpm:"lib64tiff3-devel~3.8.2~13.2mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64tiff3-static-devel", rpm:"lib64tiff3-static-devel~3.8.2~13.2mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "MNDK_2009.0")
{

  if ((res = isrpmvuln(pkg:"libtiff3", rpm:"libtiff3~3.8.2~12.3mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libtiff3-devel", rpm:"libtiff3-devel~3.8.2~12.3mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libtiff3-static-devel", rpm:"libtiff3-static-devel~3.8.2~12.3mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libtiff-progs", rpm:"libtiff-progs~3.8.2~12.3mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libtiff", rpm:"libtiff~3.8.2~12.3mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64tiff3", rpm:"lib64tiff3~3.8.2~12.3mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64tiff3-devel", rpm:"lib64tiff3-devel~3.8.2~12.3mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64tiff3-static-devel", rpm:"lib64tiff3-static-devel~3.8.2~12.3mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
