###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2018_1421_1.nasl 12497 2018-11-23 08:28:21Z cfischer $
#
# SuSE Update for Recommended openSUSE-SU-2018:1421-1 (Recommended)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.852052");
  script_version("$Revision: 12497 $");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-10-26 06:39:21 +0200 (Fri, 26 Oct 2018)");
  script_name("SuSE Update for Recommended openSUSE-SU-2018:1421-1 (Recommended)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.0");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2018-05/msg00102.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Recommended'
  package(s) announced via the openSUSE-SU-2018:1421_1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"GraphicsMagick was updated to 1.3.29:

  * Security Fixes:

  - GraphicsMagick is now participating in Google's oss-fuzz project

  - JNG: Require that the embedded JPEG image have the same dimensions as
  the JNG image as provided by JHDR. Avoids a heap write overflow.

  - MNG: Arbitrarily limit the number of loops which may be requested by
  the MNG LOOP chunk to 512 loops, and provide the '-define
  mng:maximum-loops=value' option in case the user wants to change the
  limit.  This fixes a denial of service caused by large LOOP
  specifications.

  * Bug fixes:

  - DICOM: Pre/post rescale functions are temporarily disabled (until the
  implementation is fixed).

  - JPEG: Fix regression in last release in which reading some JPEG files
  produces the error 'Improper call to JPEG library in state 201'.

  - ICON: Some DIB-based Windows ICON files were reported as corrupt to an
  unexpectedly missing opacity mask image.

  - In-memory Blob I/O: Don't implicitly increase the allocation size due
  to seek offsets.

  - MNG: Detect and handle failure to allocate global PLTE. Fix divide by
  zero.

  - DrawGetStrokeDashArray(): Check for failure to allocate memory.

  - BlobToImage(): Now produces useful exception reports to cover the
  cases where 'magick' was not set and the file format could not be
  deduced from its header.

  * API Updates:

  - Wand API: Added MagickIsPaletteImage(), MagickIsOpaqueImage(),
  MagickIsMonochromeImage(), MagickIsGrayImage(), MagickHasColormap()
  based on contributions by Troy Patteson.

  - New structure ImageExtra added and Image 'clip_mask' member is
  replaced by 'extra' which points to private ImageExtra allocation. The
  ImageGetClipMask() function now provides access to the clip mask image.

  - New structure DrawInfoExtra and DrawInfo 'clip_path' is replaced by
  'extra' which points to private DrawInfoExtra allocation.  The
  DrawInfoGetClipPath() function now provides access to the clip path.

  - New core library functions: GetImageCompositeMask(),
  CompositeMaskImage(), CompositePathImage(), SetImageCompositeMask(),
  ImageGetClipMask(), ImageGetCompositeMask(), DrawInfoGetClipPath(),
  DrawInfoGetCompositePath()

  - Deprecated core library functions: RegisterStaticModules(),
  UnregisterStaticModules().

  * Feature improvements:

  - Static modules (in static library or shared library without
  dynamically loadable modules) are now lazy-loaded using the same
  external interface as the lazy-loader for dynamic modules.  This
  results in more similarity between the builds and reduces the fixed
  initialization overhead by only initializing th ...

  Description truncated, please see the referenced URL(s) for more information.");

  script_tag(name:"affected", value:"Recommended on openSUSE Leap 15.0.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "openSUSELeap15.0")
{

  if ((res = isrpmvuln(pkg:"GraphicsMagick", rpm:"GraphicsMagick~1.3.29~lp150.3.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"GraphicsMagick-debuginfo", rpm:"GraphicsMagick-debuginfo~1.3.29~lp150.3.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"GraphicsMagick-debugsource", rpm:"GraphicsMagick-debugsource~1.3.29~lp150.3.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"GraphicsMagick-devel", rpm:"GraphicsMagick-devel~1.3.29~lp150.3.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libGraphicsMagick++-Q16-12", rpm:"libGraphicsMagick++-Q16-12~1.3.29~lp150.3.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libGraphicsMagick++-Q16-12-debuginfo", rpm:"libGraphicsMagick++-Q16-12-debuginfo~1.3.29~lp150.3.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libGraphicsMagick++-devel", rpm:"libGraphicsMagick++-devel~1.3.29~lp150.3.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libGraphicsMagick-Q16-3", rpm:"libGraphicsMagick-Q16-3~1.3.29~lp150.3.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libGraphicsMagick-Q16-3-debuginfo", rpm:"libGraphicsMagick-Q16-3-debuginfo~1.3.29~lp150.3.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libGraphicsMagick3-config", rpm:"libGraphicsMagick3-config~1.3.29~lp150.3.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libGraphicsMagickWand-Q16-2", rpm:"libGraphicsMagickWand-Q16-2~1.3.29~lp150.3.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libGraphicsMagickWand-Q16-2-debuginfo", rpm:"libGraphicsMagickWand-Q16-2-debuginfo~1.3.29~lp150.3.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perl-GraphicsMagick", rpm:"perl-GraphicsMagick~1.3.29~lp150.3.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perl-GraphicsMagick-debuginfo", rpm:"perl-GraphicsMagick-debuginfo~1.3.29~lp150.3.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
