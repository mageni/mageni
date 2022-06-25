# Copyright (C) 2020 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112799");
  script_version("2020-08-10T13:48:35+0000");
  script_tag(name:"last_modification", value:"2020-08-11 10:23:00 +0000 (Tue, 11 Aug 2020)");
  script_tag(name:"creation_date", value:"2020-08-06 12:54:00 +0000 (Thu, 06 Aug 2020)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Elegant Themes Extra Theme 2.0 <= 4.5.2 Authenticated Arbitrary File Upload Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_theme_http_detect.nasl");
  script_mandatory_keys("wordpress/theme/extra/detected");

  script_tag(name:"summary", value:"The WordPress theme Extra by Elegant Themes is prone to an authenticated arbitrary file upload vulnerability.");

  script_tag(name:"insight", value:"The theme uses a client-side file type verification check, but it was missing a server-side verification check.
  This flaw made it possible for authenticated attackers to easily bypass the JavaScript client-side check and upload
  malicious PHP files to a targeted website.

  An attacker could easily use a malicious file uploaded via this method to completely take over a site.");

  script_tag(name:"impact", value:"This flaw gave authenticated attackers, with contributor-level or above capabilities,
  the ability to upload arbitrary files, including PHP files, and achieve remote code execution on a vulnerable site's server.");

  script_tag(name:"affected", value:"WordPress Extra theme by Elegant Themes versions 2.0 through 4.5.2.");

  script_tag(name:"solution", value:"Update to version 4.5.3 or later.");

  script_xref(name:"URL", value:"https://www.wordfence.com/blog/2020/08/critical-vulnerability-exposes-over-700000-sites-using-divi-extra-and-divi-builder/");

  exit(0);
}

CPE = "cpe:/a:elegantthemes:extra";

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) ) exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_in_range( version: version, test_version: "2.0", test_version2: "4.5.2" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "4.5.3", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
