# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.113697");
  script_version("2020-06-03T11:54:33+0000");
  script_tag(name:"last_modification", value:"2020-06-04 10:51:29 +0000 (Thu, 04 Jun 2020)");
  script_tag(name:"creation_date", value:"2020-06-03 11:38:42 +0000 (Wed, 03 Jun 2020)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2020-12675");

  script_name("WordPress MapPress Plugin < 2.54.6 RCE Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("mappress-google-maps-for-wordpress/detected");

  script_tag(name:"summary", value:"The WordPress plugin MapPress is prone to a remote code execution (RCE) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability exists because of incorrectly implemented capability checks for AJAX functions
  related to creation/retrieval/deletion of PHP template files, leading to remote code execution.");

  script_tag(name:"impact", value:"Successful exploitation would allow an authenticated attacker to
  execute arbitrary code on the target machine.");

  script_tag(name:"affected", value:"WordPress MapPress plugin through version 2.54.5.");

  script_tag(name:"solution", value:"Update to version 2.54.6.");

  script_xref(name:"URL", value:"https://blog.alertlogic.com/alert-logic-threat-research-team-identifies-new-vulnerability-cve-2020-12675-in-mappress-plugin-for-wordpress/");
  script_xref(name:"URL", value:"https://wordpress.org/plugins/mappress-google-maps-for-wordpress/#developers");

  exit(0);
}

CPE = "cpe:/a:chrisvrichardson:mappress-google-maps-for-wordpress";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) ) exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "2.54.6" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.54.6", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );