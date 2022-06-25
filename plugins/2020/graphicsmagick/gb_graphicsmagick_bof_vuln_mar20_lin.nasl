# Copyright (C) 2020 Greenbone Networks GmbH
# Some text descriptions might be excerpted from the referenced
# advisories, and are Copyright (C) by the respective right holder(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.107808");
  script_version("2020-04-22T10:20:43+0000");
  script_tag(name:"last_modification", value:"2020-04-23 10:03:00 +0000 (Thu, 23 Apr 2020)");
  script_tag(name:"creation_date", value:"2020-04-22 12:15:06 +0200 (Wed, 22 Apr 2020)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2020-10938");

  script_name("GraphicsMagick < 1.3.35 heap-based Buffer Overflow vulnerability (Linux)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("os_detection.nasl", "gb_graphicsmagick_detect_lin.nasl");
  script_mandatory_keys("Host/runs_unixoide", "GraphicsMagick/Linux/Ver");

  script_tag(name:"summary", value:"GraphicsMagick is prone to an integer overflow and resultant heap-based
  buffer overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"GraphicsMagick has an integer overflow and resultant heap-based buffer
  overflow in HuffmanDecodeImage in magick/compress.c.");

  script_tag(name:"impact", value:"An attacker attempting to abuse a buffer overflow for a more specific
  purpose other than crashing the target system, can purposely overwrite important values in the call stack
  of the target machine such as the instruction pointer (IP) or base pointer (BP) in order to execute his or
  her potentially malicious unsigned code.");

  script_tag(name:"affected", value:"GraphicsMagick prior to version 1.3.35.");

  script_tag(name:"solution", value:"Update to GraphicsMagick version 1.3.35 or later.");

  script_xref(name:"URL", value:"https://sourceforge.net/p/graphicsmagick/code/ci/5b4dd7c6674140a115ec9424c8d19c6a458fac3e/");

  exit(0);
}

CPE = "cpe:/a:graphicsmagick:graphicsmagick";

include("host_details.inc");
include("version_func.inc");

if( isnull( port = get_app_port( cpe:CPE ) ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

vers = infos["version"];
path = infos["location"];

if( version_is_less( version:vers, test_version:"1.3.35" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"1.3.35", install_path:path );
  security_message( data:report, port:port );
  exit( 0 );
}

exit( 99 );
