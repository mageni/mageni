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
  script_oid("1.3.6.1.4.1.25623.1.0.113330");
  script_version("2019-04-03T09:59:09+0000");
  script_tag(name:"last_modification", value:"2019-04-03 09:59:09 +0000 (Wed, 03 Apr 2019)");
  script_tag(name:"creation_date", value:"2019-02-07 13:20:22 +0200 (Thu, 07 Feb 2019)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_cve_id("CVE-2018-20184", "CVE-2018-20185", "CVE-2018-20189");
  script_bugtraq_id(106227, 106229);

  script_name("GraphicsMagick <= 1.3.31 Multiple Vulnerabilities (Windows)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("os_detection.nasl", "gb_graphicsmagick_detect_win.nasl");
  script_mandatory_keys("Host/runs_windows", "GraphicsMagick/Win/Installed");

  script_tag(name:"summary", value:"GraphicsMagick is prone to multiple vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Following vulnerabilities exist:

  - There is a heap-based buffer overflow in the WriteTGAImage function of tga.c,
    which allows attackers to cause a denial of service via a crafted image file,
    because the number of rows or columns can exceed the pixel-dimension
    restrictions of the TGA specification.

  - There is a heap-based buffer over-read in the ReadBMP Image function of bmp.c,
    which allows attackers to cause a denial of service via a crafted bmp image file.
    This only affects GraphicsMagick installations on 32-bit platforms
    with customized BMP limits.

  - The ReadDIBImage of dib.c has a vulnerability allowing a crash and denial of service
    via a dib file that is crafted to appear with direct pixel values and also colomapping
    and therefore lacks indexes initialization.");
  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to cause a denial of service.");
  script_tag(name:"affected", value:"GraphicsMagick through version 1.3.31.");
  script_tag(name:"solution", value:"No known solution is available as of 03rd April, 2019.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2018/12/msg00018.html");

  exit(0);
}

CPE = "cpe:/a:graphicsmagick:graphicsmagick";

include("host_details.inc");
include("version_func.inc");

os_arch = get_kb_item("SMB/Windows/Arch");
if( "x64" >< os_arch ) CPE = CPE + ":x64";

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! version = get_app_version( cpe: CPE, port: port ) ) exit( 0 );

if( version_is_less_equal( version: version, test_version: "1.3.31" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "NoneAvailable" );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
