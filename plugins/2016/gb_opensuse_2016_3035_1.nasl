###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2016_3035_1.nasl 14110 2019-03-12 09:28:23Z cfischer $
#
# SuSE Update for tiff openSUSE-SU-2016:3035-1 (tiff)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.851447");
  script_version("$Revision: 14110 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-12 10:28:23 +0100 (Tue, 12 Mar 2019) $");
  script_tag(name:"creation_date", value:"2016-12-08 05:33:44 +0100 (Thu, 08 Dec 2016)");
  script_cve_id("CVE-2014-8127", "CVE-2015-7554", "CVE-2015-8665", "CVE-2015-8683",
                "CVE-2016-3622", "CVE-2016-3658", "CVE-2016-5321", "CVE-2016-5323",
                "CVE-2016-5652", "CVE-2016-5875", "CVE-2016-9273", "CVE-2016-9297",
                "CVE-2016-9448", "CVE-2016-9453");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for tiff openSUSE-SU-2016:3035-1 (tiff)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'tiff'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Tiff was updated to version 4.0.7. This update fixes the following issues:

  * libtiff/tif_aux.c
  + Fix crash in TIFFVGetFieldDefaulted() when requesting Predictor tag
  and that the zip/lzw codec is not configured.

  * libtiff/tif_compress.c
  + Make TIFFNoDecode() return 0 to indicate an error and make upper
  level read routines treat it accordingly.

  * libtiff/tif_dir.c
  + Discard values of SMinSampleValue and SMaxSampleValue when they have
  been read and the value of SamplesPerPixel is changed afterwards
  (like when reading a OJPEG compressed image with a missing
  SamplesPerPixel tag, and whose photometric is RGB or YCbCr, forcing
  SamplesPerPixel being 3). Otherwise when rewriting the directory
  (for example with tiffset, we will expect 3 values whereas the array
  had been allocated with just
  one), thus causing a out of bound read access. (CVE-2014-8127,
  boo#914890, duplicate: CVE-2016-3658, boo#974840)

  * libtiff/tif_dirread.c
  + In TIFFFetchNormalTag(), do not dereference NULL pointer when values
  of tags with TIFF_SETGET_C16_ASCII/TIFF_SETGET_C32_ASCII access are
  0-byte arrays. (CVE-2016-9448, boo#1011103)
  + In TIFFFetchNormalTag(), make sure that values of tags with
  TIFF_SETGET_C16_ASCII/TIFF_SETGET_C32_ASCII access are null
  terminated, to avoid potential read outside buffer in
  _TIFFPrintField(). (CVE-2016-9297, boo#1010161)
  + Prevent reading ColorMap or TransferFunction if BitsPerPixel   24,
  so as to avoid huge memory allocation and file read attempts
  + Reject images with OJPEG compression that have no
  TileOffsets/StripOffsets tag, when OJPEG compression is disabled.
  Prevent null pointer dereference in TIFFReadRawStrip1() and other
  functions that expect td_stripbytecount to be non NULL.

  + When compiled with DEFER_STRILE_LOAD, fix regression, when reading a
  one-strip file without a StripByteCounts tag.
  + Workaround false positive warning of Clang Static Analyzer about
  null pointer dereference in TIFFCheckDirOffset().

  * libtiff/tif_dirwrite.c
  + Avoid null pointer dereference on td_stripoffset when writing
  directory, if FIELD_STRIPOFFSETS was artificially set for a hack
  case in OJPEG case. Fixes (CVE-2014-8127, boo#914890, duplicate:
  CVE-2016-3658, ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"tiff on openSUSE 13.2");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSE13\.2");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);
res = "";

if(release == "openSUSE13.2")
{

  if ((res = isrpmvuln(pkg:"libtiff-devel", rpm:"libtiff-devel~4.0.7~10.35.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libtiff5", rpm:"libtiff5~4.0.7~10.35.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libtiff5-debuginfo", rpm:"libtiff5-debuginfo~4.0.7~10.35.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tiff", rpm:"tiff~4.0.7~10.35.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tiff-debuginfo", rpm:"tiff-debuginfo~4.0.7~10.35.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tiff-debugsource", rpm:"tiff-debugsource~4.0.7~10.35.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libtiff-devel-32bit", rpm:"libtiff-devel-32bit~4.0.7~10.35.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libtiff5-32bit", rpm:"libtiff5-32bit~4.0.7~10.35.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libtiff5-debuginfo-32bit", rpm:"libtiff5-debuginfo-32bit~4.0.7~10.35.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
