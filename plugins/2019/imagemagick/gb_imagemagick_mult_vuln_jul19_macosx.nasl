# Copyright (C) 2019 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.113428");
  script_version("2019-07-15T12:28:05+0000");
  script_tag(name:"last_modification", value:"2019-07-15 12:28:05 +0000 (Mon, 15 Jul 2019)");
  script_tag(name:"creation_date", value:"2019-07-15 10:59:22 +0000 (Mon, 15 Jul 2019)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"executable_version");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2019-13295", "CVE-2019-13296", "CVE-2019-13297", "CVE-2019-13298", "CVE-2019-13299",
  "CVE-2019-13300", "CVE-2019-13301", "CVE-2019-13302", "CVE-2019-13303", "CVE-2019-13304", "CVE-2019-13305",
  "CVE-2019-13306", "CVE-2019-13307", "CVE-2019-13308", "CVE-2019-13309", "CVE-2019-13310", "CVE-2019-13311", "CVE-2019-13391");

  script_name("ImageMagick <= 7.0.8-50 Multiple Vulnerabilities (Mac OS X)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_imagemagick_detect_macosx.nasl");
  script_mandatory_keys("ImageMagick/MacOSX/Version");

  script_tag(name:"summary", value:"ImageMagick is prone to multiple vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Following vulnerabilities exist:

  - Heap-based buffer over-read at MagickCore/threshold in AdaptiveThresholdImage
    because a width of zero is mishandled.

  - Direct memory leaks in AcquireMagickMemory because of an error in CLIListOperatorImages
    in MagickWand/operation.c for a NULL value.

  - Heap-based buffer over-read at MagickCore/threshold.c in AdaptiveThresholdImage
    because a height of zero is mishandled.

  - Heap-based buffer over-read at MagickCore/pixel-accessor.h in SetPixelViaPixelInfo
    because of a MagickCore/enhance.c error.

  - Heap-based buffer over-read at MagickCore/pixel-accessor.h in GetPixelChannel.

  - Heap-based buffer overflow at MagickCore/statistic.c in EvaluateImages
    because of mishandling columns.

  - Memory leaks in AcquireMagickMemory because of an AnnotateImage error.

  - Heap-based buffer over-read in MagickCore/fourier.c in ComplexImages.

  - Heap-based buffer over-read in MagickCore/composite.c in CompositeImages.

  - Stack-based buffer overflow at coders/pnm.c in WritePNMImage
    because of mispalces assignment.

  - Stack-based buffer overflow at coders/pnm.c in WritePNMImage
    because of a misplaced strncpy and an off-by-one error.

  - Stack-based buffer overflow at coders/pnm.c in WritePNMImage
    because of off-by-one errors.

  - Heap-based buffer overflow at MagickCore/statistic.c in EvaluateImages
    because of mishandling rows.

  - Heap-based buffer overflow in MagickCore/fourier.c in ComplexImage.

  - Memory leaks at AcquireMagickMemory because of mishandling the NoSuchImage error
    in CLIListOperatorImages in MagickWand/operation.c.

  - Memory leaks at AcquireMagickMemory because of an error in MagickWand/mogrify.c.

  - Memory leaks at AcquireMagickMemory because of a wand/mogrify.c error.

  - ComplexImages in MagickCore/fourier.c has a heap-based buffer over-read
    because of incorrect calls to GetCacheViewVirtualPixels.");
  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to read sensitive information
  or execute arbitrary code on the target machine.");
  script_tag(name:"affected", value:"ImageMagick through version 7.0.8-50.");
  script_tag(name:"solution", value:"Update to version 7.0.8-51.");

  script_xref(name:"URL", value:"https://github.com/ImageMagick/ImageMagick/issues/1609");
  script_xref(name:"URL", value:"https://github.com/ImageMagick/ImageMagick/issues/1611");
  script_xref(name:"URL", value:"https://github.com/ImageMagick/ImageMagick/issues/1610");
  script_xref(name:"URL", value:"https://github.com/ImageMagick/ImageMagick/issues/1608");
  script_xref(name:"URL", value:"https://github.com/ImageMagick/ImageMagick/issues/1604");
  script_xref(name:"URL", value:"https://github.com/ImageMagick/ImageMagick/issues/1586");
  script_xref(name:"URL", value:"https://github.com/ImageMagick/ImageMagick/issues/1585");
  script_xref(name:"URL", value:"https://github.com/ImageMagick/ImageMagick/issues/1589");
  script_xref(name:"URL", value:"https://github.com/ImageMagick/ImageMagick/issues/1597");
  script_xref(name:"URL", value:"https://github.com/ImageMagick/ImageMagick/issues/1603");
  script_xref(name:"URL", value:"https://github.com/ImageMagick/ImageMagick/issues/1614");
  script_xref(name:"URL", value:"https://github.com/ImageMagick/ImageMagick/issues/1613");
  script_xref(name:"URL", value:"https://github.com/ImageMagick/ImageMagick/issues/1612");
  script_xref(name:"URL", value:"https://github.com/ImageMagick/ImageMagick/issues/1615");
  script_xref(name:"URL", value:"https://github.com/ImageMagick/ImageMagick/issues/1595");
  script_xref(name:"URL", value:"https://github.com/ImageMagick/ImageMagick/issues/1616");
  script_xref(name:"URL", value:"https://github.com/ImageMagick/ImageMagick/issues/1623");
  script_xref(name:"URL", value:"https://github.com/ImageMagick/ImageMagick/issues/1588");

  exit(0);
}

CPE = "cpe:/a:imagemagick:imagemagick";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE ) ) exit( 0 );
version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "7.0.8.51" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "7.0.8-51", install_path: location );
  security_message( data: report, port: 0 );
  exit( 0 );
}

exit( 99 );
