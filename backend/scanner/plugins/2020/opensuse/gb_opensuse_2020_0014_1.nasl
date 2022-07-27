# Copyright (C) 2020 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.852983");
  script_version("2020-01-16T07:19:44+0000");
  script_cve_id("CVE-2019-11037");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-01-16 07:19:44 +0000 (Thu, 16 Jan 2020)");
  script_tag(name:"creation_date", value:"2020-01-14 04:01:21 +0000 (Tue, 14 Jan 2020)");
  script_name("openSUSE Update for php7-imagick openSUSE-SU-2020:0014-1 (php7-imagick)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.1");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2020-01/msg00016.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'php7-imagick'
  package(s) announced via the openSUSE-SU-2020:0014_1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for php7-imagick fixes the following issues:

  Upgrade to version 3.4.4:

  Added:

  * function Imagick::optimizeImageTransparency()

  * METRIC_STRUCTURAL_SIMILARITY_ERROR

  * METRIC_STRUCTURAL_DISSIMILARITY_ERROR

  * COMPRESSION_ZSTD

  * COMPRESSION_WEBP

  * CHANNEL_COMPOSITE_MASK

  * FILTER_CUBIC_SPLINE - 'Define the lobes with the -define
  filter:lobes={2, 3, 4}

  * Imagick now explicitly conflicts with the Gmagick extension.

  Fixes:

  * Correct version check to make RemoveAlphaChannel and
  FlattenAlphaChannel be available when using Imagick with ImageMagick
  version 6.7.8-x

  * Bug 77128 - Imagick::setImageInterpolateMethod() not available on
  Windows

  * Prevent memory leak when ImagickPixel::__construct called after object
  instantiation.

  * Prevent segfault when ImagickPixel internal constructor not called.

  * Imagick::setResourceLimit support for values larger than 2GB (2^31) on
  32bit platforms.

  * Corrected memory overwrite in Imagick::colorDecisionListImage()

  * Bug 77791 - ImagickKernel::fromMatrix() out of bounds write. Fixes
  CVE-2019-11037, boo#1135418

  The following functions have been deprecated:

  * ImagickDraw, matte

  * Imagick::averageimages

  * Imagick::colorfloodfillimage

  * Imagick::filter

  * Imagick::flattenimages

  * Imagick::getimageattribute

  * Imagick::getimagechannelextrema

  * Imagick::getimageclipmask

  * Imagick::getimageextrema

  * Imagick::getimageindex

  * Imagick::getimagematte

  * Imagick::getimagemattecolor

  * Imagick::getimagesize

  * Imagick::mapimage

  * Imagick::mattefloodfillimage

  * Imagick::medianfilterimage

  * Imagick::mosaicimages

  * Imagick::orderedposterizeimage

  * Imagick::paintfloodfillimage

  * Imagick::paintopaqueimage

  * Imagick::painttransparentimage

  * Imagick::radialblurimage

  * Imagick::recolorimage

  * Imagick::reducenoiseimage

  * Imagick::roundcornersimage

  * Imagick::roundcorners

  * Imagick::setimageattribute

  * Imagick::setimagebias

  * Imagick::setimageclipmask

  * Imagick::setimageindex

  * Imagick::setimagemattecolor

  * Imagick::setimagebiasquantum

  * Imagick::setimageopacity

  * Imagick::transformimage


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2020-14=1

  - openSUSE Backports SLE-15-SP1:

  zypper in -t patch openSUSE-2020-14=1");

  script_tag(name:"affected", value:"'php7-imagick' package(s) on openSUSE Leap 15.1.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "openSUSELeap15.1") {

  if(!isnull(res = isrpmvuln(pkg:"php7-imagick", rpm:"php7-imagick~3.4.4~lp151.8.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-imagick-debuginfo", rpm:"php7-imagick-debuginfo~3.4.4~lp151.8.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-imagick-debugsource", rpm:"php7-imagick-debugsource~3.4.4~lp151.8.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if (__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
