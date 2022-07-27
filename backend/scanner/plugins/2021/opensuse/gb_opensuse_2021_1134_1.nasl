# Copyright (C) 2021 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
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
  script_oid("1.3.6.1.4.1.25623.1.0.854051");
  script_version("2021-08-24T09:58:36+0000");
  script_cve_id("CVE-2020-15999", "CVE-2020-35653", "CVE-2020-35654", "CVE-2020-35655", "CVE-2021-25289", "CVE-2021-25290", "CVE-2021-25291", "CVE-2021-25292", "CVE-2021-25293", "CVE-2021-27921", "CVE-2021-27922", "CVE-2021-27923", "CVE-2021-34552");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-08-25 10:27:37 +0000 (Wed, 25 Aug 2021)");
  script_tag(name:"creation_date", value:"2021-08-11 03:02:13 +0000 (Wed, 11 Aug 2021)");
  script_name("openSUSE: Security Advisory for python-CairoSVG, (openSUSE-SU-2021:1134-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.2");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:1134-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/N6MMS3NOFXF2TZBZ5M3EC6VOB65FRP4I");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-CairoSVG, '
  package(s) announced via the openSUSE-SU-2021:1134-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for python-CairoSVG, python-Pillow fixes the following issues:

     Update to version 2.5.1.

  * Security fix: When processing SVG files, CairoSVG was using two regular
       expressions which are vulnerable to Regular Expression Denial of Service
       (REDoS). If an attacker provided a malicious SVG, it could make CairoSVG
       get stuck processing the file for a very long time.

  * Fix marker positions for unclosed paths

  * Follow hint when only output_width or output_height is set

  * Handle opacity on raster images

  * Dont crash when use tags reference unknown tags

  * Take care of the next letter when A/a is replaced by l

  * Fix misalignment in node.vertices

     Updates for version 2.5.0.

  * Drop support of Python 3.5, add support of Python 3.9.

  * Add EPS export

  * Add background-color, negate-colors, and invert-images options

  * Improve support for font weights

  * Fix opacity of patterns and gradients

  * Support auto-start-reverse value for orient

  * Draw images contained in defs

  * Add Exif transposition support

  * Handle dominant-baseline

  * Support transform-origin

     python-Pillow update to version 8.3.1:

  * Catch OSError when checking if fp is sys.stdout #5585 [radarhere]

  * Handle removing orientation from alternate types of EXIF data #5584
       [radarhere]

  * Make Image.__array__ take optional dtype argument #5572 [t-vi, radarhere]

  * Use snprintf instead of sprintf. CVE-2021-34552 #5567 [radarhere]

  * Limit TIFF strip size when saving with LibTIFF #5514 [kmilos]

  * Allow ICNS save on all operating systems #4526 [baletu, radarhere,
       newpanjing, hugovk]

  * De-zigzag JPEG&#x27 s DQT when loading  deprecate convert_dict_qtables #4989
       [gofr, radarhere]

  * Replaced xml.etree.ElementTree #5565 [radarhere]

  * Moved CVE image to pillow-depends #5561 [radarhere]

  * Added tag data for IFD groups #5554 [radarhere]

  * Improved ImagePalette #5552 [radarhere]

  * Add DDS saving #5402 [radarhere]

  * Improved getxmp() #5455 [radarhere]

  * Convert to float for comparison with float in IFDRational __eq__ #5412
       [radarhere]

  * Allow getexif() to access TIFF tag_v2 data #5416 [radarhere]

  * Read FITS image mode and size #5405 [radarhere]

  * Merge parallel horizontal edges in ImagingDrawPolygon #5347 [radarhere,
       hrdrq]

  * Use transparency behind first GIF frame and when disposing to background
       #5557 [radarhere, zewt]

  * Avoid unstable nature of qsort in Quant.c #5367 [radarhe ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'python-CairoSVG, ' package(s) on openSUSE Leap 15.2.");

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

if(release == "openSUSELeap15.2") {

  if(!isnull(res = isrpmvuln(pkg:"python3-CairoSVG", rpm:"python3-CairoSVG~2.5.1~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-Pillow-debuginfo", rpm:"python-Pillow-debuginfo~8.3.1~lp152.5.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-Pillow-debugsource", rpm:"python-Pillow-debugsource~8.3.1~lp152.5.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-Pillow", rpm:"python3-Pillow~8.3.1~lp152.5.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-Pillow-debuginfo", rpm:"python3-Pillow-debuginfo~8.3.1~lp152.5.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-Pillow-tk", rpm:"python3-Pillow-tk~8.3.1~lp152.5.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-Pillow-tk-debuginfo", rpm:"python3-Pillow-tk-debuginfo~8.3.1~lp152.5.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);