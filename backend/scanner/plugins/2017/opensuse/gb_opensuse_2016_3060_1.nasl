###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2016_3060_1.nasl 12381 2018-11-16 11:16:30Z cfischer $
#
# SuSE Update for GraphicsMagick openSUSE-SU-2016:3060-1 (GraphicsMagick)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.851511");
  script_version("$Revision: 12381 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2017-02-22 15:17:51 +0100 (Wed, 22 Feb 2017)");
  script_cve_id("CVE-2014-9805", "CVE-2014-9807", "CVE-2014-9809", "CVE-2014-9815",
                "CVE-2014-9817", "CVE-2014-9820", "CVE-2014-9831", "CVE-2014-9834",
                "CVE-2014-9835", "CVE-2014-9837", "CVE-2014-9845", "CVE-2014-9846",
                "CVE-2014-9853", "CVE-2016-5118", "CVE-2016-6823", "CVE-2016-7101",
                "CVE-2016-7515", "CVE-2016-7522", "CVE-2016-7528", "CVE-2016-7529",
                "CVE-2016-7531", "CVE-2016-7533", "CVE-2016-7537", "CVE-2016-7800",
                "CVE-2016-7996", "CVE-2016-7997", "CVE-2016-8682", "CVE-2016-8683",
                "CVE-2016-8684", "CVE-2016-8862", "CVE-2016-9556");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for GraphicsMagick openSUSE-SU-2016:3060-1 (GraphicsMagick)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'GraphicsMagick'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"This update for GraphicsMagick fixes the following issues:

  - a possible shell execution attack was fixed. if the first character of
  an input filename for 'convert' was a 'pipe' char then the remainder of the
  filename was passed to the shell (CVE-2016-5118, boo#982178)

  - Maliciously crafted pnm files could crash GraphicsMagick (CVE-2014-9805,
  [boo#983752])

  - Prevent overflow in rle files (CVE-2014-9846, boo#983521)

  - Fix a double free in pdb coder (CVE-2014-9807, boo#983794)

  - Fix a possible crash due to corrupted xwd images (CVE-2014-9809,
  boo#983799)

  - Fix a possible crash due to corrupted wpg images (CVE-2014-9815,
  boo#984372)

  - Fix a heap buffer overflow in pdb file handling (CVE-2014-9817,
  boo#984400)

  - Fix a heap overflow in xpm files (CVE-2014-9820, boo#984150)

  - Fix a heap overflow in pict files (CVE-2014-9834, boo#984436)

  - Fix a heap overflow in wpf files (CVE-2014-9835, CVE-2014-9831,
  boo#984145, boo#984375)

  - Additional PNM sanity checks (CVE-2014-9837, boo#984166)

  - Fix a possible crash due to corrupted dib file (CVE-2014-9845,
  boo#984394)

  - Fix out of bound in quantum handling (CVE-2016-7529, boo#1000399)

  - Fix out of bound access in xcf file coder (CVE-2016-7528, boo#1000434)

  - Fix handling of corrupted lle files (CVE-2016-7515, boo#1000689)

  - Fix out of bound access for malformed psd file (CVE-2016-7522,
  boo#1000698)

  - Fix out of bound access for pbd files (CVE-2016-7531, boo#1000704)

  - Fix out of bound access in corrupted wpg files (CVE-2016-7533,
  boo#1000707)

  - Fix out of bound access in corrupted pdb files (CVE-2016-7537,
  boo#1000711)

  - BMP Coder Out-Of-Bounds Write Vulnerability (CVE-2016-6823, boo#1001066)

  - SGI Coder Out-Of-Bounds Read Vulnerability (CVE-2016-7101, boo#1001221)

  - Divide by zero in WriteTIFFImage (do not divide by zero in
  WriteTIFFImage, boo#1002206)

  - Buffer overflows in SIXEL, PDB, MAP, and TIFF coders (fix buffer
  overflow, boo#1002209)

  - 8BIM/8BIMW unsigned underflow leads to heap overflow (CVE-2016-7800,
  boo#1002422)

  - wpg reader issues (CVE-2016-7996, CVE-2016-7997, boo#1003629)

  - Mismatch between real filesize and header values (CVE-2016-8684,
  boo#1005123)

  - Stack-buffer read overflow while reading SCT header (CVE-2016-8682,
  boo#1005125)

  - Check that filesize is reasonable compared to the header value
  (CVE-2016-8683, boo#1005127)

  - Memory allocation failure in AcquireMagickMemory (CVE-2016-8862,
  boo#1007245)

  - heap-based buffer overflow in IsPixelGray (CVE-2016-9556, boo#1011130)");
  script_tag(name:"affected", value:"GraphicsMagick on openSUSE Leap 42.2");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap42\.2");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);
res = "";

if(release == "openSUSELeap42.2")
{

  if ((res = isrpmvuln(pkg:"GraphicsMagick", rpm:"GraphicsMagick~1.3.25~3.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"GraphicsMagick-debuginfo", rpm:"GraphicsMagick-debuginfo~1.3.25~3.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"GraphicsMagick-debugsource", rpm:"GraphicsMagick-debugsource~1.3.25~3.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"GraphicsMagick-devel", rpm:"GraphicsMagick-devel~1.3.25~3.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libGraphicsMagick++-Q16-12", rpm:"libGraphicsMagick++-Q16-12~1.3.25~3.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libGraphicsMagick++-Q16-12-debuginfo", rpm:"libGraphicsMagick++-Q16-12-debuginfo~1.3.25~3.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libGraphicsMagick++-devel", rpm:"libGraphicsMagick++-devel~1.3.25~3.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libGraphicsMagick-Q16-3", rpm:"libGraphicsMagick-Q16-3~1.3.25~3.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libGraphicsMagick-Q16-3-debuginfo", rpm:"libGraphicsMagick-Q16-3-debuginfo~1.3.25~3.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libGraphicsMagick3-config", rpm:"libGraphicsMagick3-config~1.3.25~3.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libGraphicsMagickWand-Q16-2", rpm:"libGraphicsMagickWand-Q16-2~1.3.25~3.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libGraphicsMagickWand-Q16-2-debuginfo", rpm:"libGraphicsMagickWand-Q16-2-debuginfo~1.3.25~3.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perl-GraphicsMagick", rpm:"perl-GraphicsMagick~1.3.25~3.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perl-GraphicsMagick-debuginfo", rpm:"perl-GraphicsMagick-debuginfo~1.3.25~3.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
