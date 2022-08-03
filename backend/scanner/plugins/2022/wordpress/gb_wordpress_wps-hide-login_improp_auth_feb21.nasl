# Copyright (C) 2022 Greenbone Networks GmbH
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

CPE = "cpe:/a:wpserveur:wps-hide-login";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127115");
  script_version("2022-08-02T10:11:24+0000");
  script_tag(name:"last_modification", value:"2022-08-02 10:11:24 +0000 (Tue, 02 Aug 2022)");
  script_tag(name:"creation_date", value:"2022-08-01 11:19:34 +0000 (Mon, 01 Aug 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-05-05 18:30:00 +0000 (Wed, 05 May 2021)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2021-3332");

  script_name("WordPress WPS Hide Login Plugin <= 1.6.1 Improper Authentication Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/wps-hide-login/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'WPS Hide Login' is prone to an improper
  authentication vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The plugin allows remote attackers to bypass a protection
  mechanism via post_password.");

  script_tag(name:"affected", value:"WordPress 'WPS Hide Login' plugin version 1.6.1 and prior.");

  script_tag(name:"solution", value:"Update to version 1.7 or later.");

  script_xref(name:"URL", value:"https://blog.sebastianschmitt.eu/security/wps-hide-login-1-6-1-protection-bypass-cve-2021-3332/");
  script_xref(name:"URL", value:"https://wordpress.org/plugins/wps-hide-login/#developers");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less_equal( version: version, test_version: "1.6.1" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.7", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
