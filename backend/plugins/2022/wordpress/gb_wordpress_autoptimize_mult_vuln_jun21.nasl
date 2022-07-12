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

CPE = "cpe:/a:autoptimize:autoptimize";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127061");
  script_version("2022-06-30T09:43:33+0000");
  script_tag(name:"last_modification", value:"2022-06-30 09:43:33 +0000 (Thu, 30 Jun 2022)");
  script_tag(name:"creation_date", value:"2022-06-24 11:23:46 +0000 (Fri, 24 Jun 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-29 11:15:00 +0000 (Tue, 29 Jun 2021)");

  script_cve_id("CVE-2021-24376", "CVE-2021-24377", "CVE-2021-24378");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Autoptimize Plugin < 2.7.8 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/autoptimize/detected");

  script_tag(name:"summary", value:"The WordPress plugin Autoptimize is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2021-24376: Arbitrary file upload via 'Import Settings'

  - CVE-2021-24377: Race condition leading to remote code execution (RCE)

  - CVE-2021-24378: Authenticated stored XSS via file upload");

  script_tag(name:"affected", value:"WordPress Autoptimize plugin prior to version 2.7.8.");

  script_tag(name:"solution", value:"Update to version 2.7.8 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/93edcc23-894a-46c2-84d2-407dcb64ba1e");
  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/85c0a564-2e56-413d-bc3a-1039343207e4");
  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/375bd694-1a30-41af-bbd4-8a8ee54f0dbf");

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

if( version_is_less( version: version, test_version: "2.7.8" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.7.8", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
