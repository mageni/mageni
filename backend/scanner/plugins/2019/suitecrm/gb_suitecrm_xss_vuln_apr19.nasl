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
  script_oid("1.3.6.1.4.1.25623.1.0.113367");
  script_version("2019-04-12T06:46:08+0000");
  script_tag(name:"last_modification", value:"2019-04-12 06:46:08 +0000 (Fri, 12 Apr 2019)");
  script_tag(name:"creation_date", value:"2019-04-08 11:42:51 +0000 (Mon, 08 Apr 2019)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2018-20816");

  script_name("SuiteCRM 7.x <= 7.8.23 and 7.10.x <= 7.10.10 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_suitecrm_detect.nasl");
  script_mandatory_keys("suitecrm/detected");

  script_tag(name:"summary", value:"SuiteCRM is prone to a Cross-Site Scripting (XSS) vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The vulnerability exists within the 'add dashboard pages' feature,
  where users can receive a malicious URL or JavaScript which is then executed.");
  script_tag(name:"impact", value:"Successful exploitation would allow an authenticated attacker to execute
  arbitrary JavaScript in the context of another user and potentially hijack
  the targeted user's session.");
  script_tag(name:"affected", value:"SuiteCRM versions 7.0.0 through 7.8.23 and 7.10.0 through 7.10.10.");
  script_tag(name:"solution", value:"Update to version 7.8.24 or 7.10.11 respectively.");

  script_xref(name:"URL", value:"https://docs.suitecrm.com/admin/releases/7.8.x/#_7_8_24");
  script_xref(name:"URL", value:"https://docs.suitecrm.com/admin/releases/7.10.x/#_7_10_11");

  exit(0);
}

CPE = "cpe:/a:suitecrm:suitecrm";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) ) exit( 0 );
version = infos["version"];
location = infos["location"];

if( version_in_range( version: version, test_version: "7.0.0", test_version2: "7.8.23" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "7.8.24", install_url: location );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "7.10.0", test_version2: "7.10.10" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "7.10.11", install_url: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
