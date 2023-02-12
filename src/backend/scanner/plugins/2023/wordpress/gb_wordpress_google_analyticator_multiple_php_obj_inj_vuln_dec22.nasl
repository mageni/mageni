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

CPE = "cpe:/a:sumo:google_analyticator";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127310");
  script_version("2023-01-25T10:11:07+0000");
  script_tag(name:"last_modification", value:"2023-01-25 10:11:07 +0000 (Wed, 25 Jan 2023)");
  script_tag(name:"creation_date", value:"2023-01-24 11:15:43 +0000 (Tue, 24 Jan 2023)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:M/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2022-3425", "CVE-2022-4323");

  script_name("WordPress Google Analyticator Plugin < 6.5.6 Multiple PHP Object Injection Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/google-analyticator/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Google Analyticator' is prone to multiple
  PHP object injection vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2022-3425, CVE-2022-4323: The plugin unserializes user input provided via the settings,
  which could allow high-privilege users such as admin to perform PHP Object Injection when a
  suitable gadget is present.");

  script_tag(name:"affected", value:"WordPress Google Analyticator plugin prior to version 6.5.6.");

  script_tag(name:"solution", value:"Update to version 6.5.6 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/df1c36bb-9861-4272-89c9-ae76e62f687c");
  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/ce8027b8-9473-463e-ba80-49b3d6d16228");

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

if ( version_is_less( version: version, test_version: "6.5.6" )) {
  report = report_fixed_ver( installed_version: version, fixed_version: "6.5.6", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
