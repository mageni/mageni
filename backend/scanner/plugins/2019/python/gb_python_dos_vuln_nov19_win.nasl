# Copyright (C) 2019 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.113561");
  script_version("2019-11-13T08:06:35+0000");
  script_tag(name:"last_modification", value:"2019-11-13 08:06:35 +0000 (Wed, 13 Nov 2019)");
  script_tag(name:"creation_date", value:"2019-11-11 15:10:49 +0000 (Mon, 11 Nov 2019)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_tag(name:"qod_type", value:"registry");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2019-5010");

  script_name("Python 2.x.x <= 2.7.11, 3.x.x <= 3.6.6 Denial of Service (DoS) Vulnerability (Windows)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_python_detect_win.nasl");
  script_mandatory_keys("python/win/detected");

  script_tag(name:"summary", value:"Python is prone to a denial of service (DoS) vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"A specially crafted X509 certificate can cause a NULL pointer dereference,
  resulting in a denial of service. An attacker can initiate or accept TLS
  connections using crafted certificates to trigger this vulnerability.");
  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to crash the application.");
  script_tag(name:"affected", value:"Python versions 2.0.0 through 2.7.11 and 3.0.0 through 3.6.6.");
  script_tag(name:"solution", value:"Update to version 2.7.12 or 3.6.7 respectively");

  script_xref(name:"URL", value:"https://talosintelligence.com/vulnerability_reports/TALOS-2019-0758");

  exit(0);
}

CPE = "cpe:/a:python:python";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE ) ) exit( 0 );
version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "2.7.12" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.7.12", install_path: location );
  security_message( data: report, port: 0 );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "3.0.0", test_version2: "3.6.6" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.6.7", install_path: location );
  security_message( data: report, port: 0 );
  exit( 0 );
}

exit( 99 );
