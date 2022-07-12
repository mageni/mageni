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
  script_oid("1.3.6.1.4.1.25623.1.0.113460");
  script_version("2019-08-15T08:59:01+0000");
  script_tag(name:"last_modification", value:"2019-08-15 08:59:01 +0000 (Thu, 15 Aug 2019)");
  script_tag(name:"creation_date", value:"2019-08-14 14:03:54 +0000 (Wed, 14 Aug 2019)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:P");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2019-10649", "CVE-2019-10650");
  script_bugtraq_id(107645, 107646);

  script_name("ImageMagick <= 7.0.8-36 Multiple Vulnerabilities (Linux)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_imagemagick_detect_lin.nasl");
  script_mandatory_keys("ImageMagick/Lin/Ver");

  script_tag(name:"summary", value:"ImageMagick is prone to multiple vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Following vulnerabilities exist:

  - There is a memory leak in the function SVGKeyValuePairs of coders/svg.c
    which allows an attacker to cause a denial of service
    via a crafted image file.

  - There is a heap-based buffer over-read in the function WriteTIFFImage
    of coders/tiff.c which allows an attacker to cause a denial of service
    or information disclosure via a crafted image file.");
  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to read sensitive information
  or crash the application.");
  script_tag(name:"affected", value:"ImageMagick through version 7.0.8-36.");
  script_tag(name:"solution", value:"Update to version 7.0.8-37.");

  script_xref(name:"URL", value:"https://github.com/ImageMagick/ImageMagick/issues/1533");
  script_xref(name:"URL", value:"https://github.com/ImageMagick/ImageMagick/issues/1532");

  exit(0);
}

CPE = "cpe:/a:imagemagick:imagemagick";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE ) ) exit( 0 );
version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "7.0.8.37" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "7.0.8-37", install_path: location );
  security_message( data: report, port: 0 );
  exit( 0 );
}

exit( 99 );
