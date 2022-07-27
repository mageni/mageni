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
  script_oid("1.3.6.1.4.1.25623.1.0.112732");
  script_version("2020-05-04T12:56:06+0000");
  script_tag(name:"last_modification", value:"2020-05-04 12:56:06 +0000 (Mon, 04 May 2020)");
  script_tag(name:"creation_date", value:"2020-04-28 11:52:00 +0000 (Tue, 28 Apr 2020)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_cve_id("CVE-2020-12073");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Responsive Ready Sites Importer Plugin < 2.2.6 IAC Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("responsive-add-ons/detected");

  script_tag(name:"summary", value:"Responsive Ready Sites Importer plugin for WordPress is prone to an incorrect access control (IAC) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Successful exploitation would allow an authenticated user, regardless of privilege level,
  the ability to execute various AJAX actions that could reset site data, inject malicious JavaScript in pages, modify theme
  customizer data, import .xml and .json files, and activate plugins, among many other actions.");

  script_tag(name:"affected", value:"WordPress Responsive Ready Sites Importer plugin before version 2.2.6.");

  script_tag(name:"solution", value:"Update to version 2.2.6 or later.");

  script_xref(name:"URL", value:"https://wordpress.org/plugins/responsive-add-ons/#developers");
  script_xref(name:"URL", value:"https://www.wordfence.com/blog/2020/03/severe-flaws-patched-in-responsive-ready-sites-importer-plugin/");

  exit(0);
}

CPE = "cpe:/a:cyberchimps:responsive-add-ons";

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) ) exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "2.2.6" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.2.6", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
