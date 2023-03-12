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

CPE = "cpe:/a:php-fusion:php-fusion";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127349");
  script_version("2023-02-22T10:10:00+0000");
  script_tag(name:"last_modification", value:"2023-02-22 10:10:00 +0000 (Wed, 22 Feb 2023)");
  script_tag(name:"creation_date", value:"2023-02-20 07:34:35 +0000 (Mon, 20 Feb 2023)");
  script_tag(name:"cvss_base", value:"2.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:S/C:N/I:N/A:P");

  script_cve_id("CVE-2021-3172");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PHPFusion < 9.03.100 DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("secpod_php_fusion_detect.nasl");
  script_mandatory_keys("php-fusion/detected");

  script_tag(name:"summary", value:"PHPFusion is prone to a denial of service (DoS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A logged in user can vote multiple times as the application
  does not limit the user to vote only once.");

  script_tag(name:"affected", value:"PHPFusion version prior to 9.03.100.");

  script_tag(name:"solution", value:"Update to version 9.03.100 or later.");

  script_xref(name:"URL", value:"https://github.com/PHPFusion/PHPFusion/issues/2351");
  script_xref(name:"URL", value:"https://github.com/PHPFusion/PHPFusion/commit/7b8df6925cc7cfd8585d4f34d9120ff3a2e5753e");

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

if( version_is_less( version: version, test_version: "9.03.100" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "9.03.100", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
