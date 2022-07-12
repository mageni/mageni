# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.113639");
  script_version("2020-02-18T11:21:33+0000");
  script_tag(name:"last_modification", value:"2020-02-19 12:05:59 +0000 (Wed, 19 Feb 2020)");
  script_tag(name:"creation_date", value:"2020-02-17 14:07:49 +0000 (Mon, 17 Feb 2020)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_tag(name:"qod_type", value:"executable_version");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_cve_id("CVE-2020-8492");

  script_name("Python 2.7.x <= 2.7.17, 3.5 <= 3.5.9, 3.6.x <= 3.6.10, 3.7.x <= 3.7.6, 3.8.x <= 3.8.1 Regular Expression Denial of Service (ReDoS) Vulnerability (MAC OS X)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_python_detect_macosx.nasl");
  script_mandatory_keys("python/macosx/detected");

  script_tag(name:"summary", value:"Python is prone to a Regular Expresson Denial of Service (ReDoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The AbtractBasicAuthHandler class of the urllib.request module uses an inefficient regular expression (catastrophic backtracking)
  which can be exploited by an attacker to cause a denial of service.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to crash the application.");

  script_tag(name:"affected", value:"Python 2.7 through 2.7.17, 3.5 through 3.5.9, 3.6 through 3.6.10, 3.7 through 3.7.6, and 3.8 through 3.8.1");

  script_tag(name:"solution", value:"No known solution is available as of 17th February, 2020. Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://bugs.python.org/issue39503");
  script_xref(name:"URL", value:"https://python-security.readthedocs.io/vuln/urllib-basic-auth-Nregex.html");


  exit(0);
}

CPE = "cpe:/a:python:python";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE ) ) exit( 0 );
version = infos["version"];
location = infos["location"];

if( version_in_range( version: version, test_version: "2.7.0", test_version2: "2.7.17" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "None", install_path: location );
  security_message( data: report, port: 0 );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "3.5.0", test_version2: "3.5.9" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "None", install_path: location );
  security_message( data: report, port: 0 );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "3.6.0", test_version2: "3.6.10" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "None", install_path: location );
  security_message( data: report, port: 0 );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "3.7.0", test_version2: "3.7.6" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "None", install_path: location );
  security_message( data: report, port: 0 );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "3.8.0", test_version2: "3.8.1" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "None", install_path: location );
  security_message( data: report, port: 0 );
  exit( 0 );
}

exit( 99 );

