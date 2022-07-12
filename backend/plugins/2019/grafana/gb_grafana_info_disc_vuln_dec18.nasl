# Copyright (C) 2019 Greenbone Networks GmbH, https://www.greenbone.net
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112497");
  script_version("2019-07-01T10:35:57+0000");
  script_tag(name:"last_modification", value:"2019-07-01 10:35:57 +0000 (Mon, 01 Jul 2019)");
  script_tag(name:"creation_date", value:"2019-07-01 11:30:11 +0200 (Mon, 01 Jul 2019)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2018-19039");
  script_bugtraq_id(105994);

  script_name("Grafana 4.1.0 through 5.3.2 Information Disclosure Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_grafana_http_detect.nasl");
  script_mandatory_keys("grafana/detected");

  script_tag(name:"summary", value:"Grafana is prone to an information disclosure vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The vulnerability allows any users with Editor or Admin permissions
  in Grafana to read any file that the Grafana process can read from the filesystem.");
  script_tag(name:"impact", value:"Successful exploitation of these vulnerabilities could lead to disclosure
  of sensitive information or addition or modification of data.");
  script_tag(name:"affected", value:"Grafana 4.1.0 through 5.3.2.");
  script_tag(name:"solution", value:"Update to version 4.6.5 or 5.3.3 respectively.");

  script_xref(name:"URL", value:"https://community.grafana.com/t/grafana-5-3-3-and-4-6-5-security-update/11961");

  exit(0);
}

CPE = "cpe:/a:grafana:grafana";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) ) exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_in_range( version: version, test_version: "4.1.0", test_version2: "4.6.4" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "4.6.5", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "5.0.0", test_version2: "5.3.2" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "5.3.3", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
