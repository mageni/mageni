# Copyright (C) 2023 Greenbone Networks GmbH
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

CPE = "cpe:/a:tipsandtricks-hq:all_in_one_wp_security_%26_firewall";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127309");
  script_version("2023-01-25T10:11:07+0000");
  script_tag(name:"last_modification", value:"2023-01-25 10:11:07 +0000 (Wed, 25 Jan 2023)");
  script_tag(name:"creation_date", value:"2023-01-24 07:15:43 +0000 (Tue, 24 Jan 2023)");
  script_tag(name:"cvss_base", value:"2.7");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:S/C:P/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2022-4346");

  script_name("WordPress All In One WP Security & Firewall Plugin < 5.1.3 Information Disclosure Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/all-in-one-wp-security-and-firewall/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'All In One WP Security & Firewall'
  is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The plugin contains a publicly accessible folder with
  configuration files and included email addresses.");

  script_tag(name:"affected", value:"WordPress All In One WP Security & Firewall plugin prior to
  version 5.1.3.");

  script_tag(name:"solution", value:"Update to version 5.1.3 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/cc05f760-983d-4dc1-afbb-6b4965aa8abe");

  exit(0);
}

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "5.1.3" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "5.1.3", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
