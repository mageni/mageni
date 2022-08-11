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
  script_oid("1.3.6.1.4.1.25623.1.0.113416");
  script_version("2019-06-24T12:56:50+0000");
  script_tag(name:"last_modification", value:"2019-06-24 12:56:50 +0000 (Mon, 24 Jun 2019)");
  script_tag(name:"creation_date", value:"2019-06-24 14:48:35 +0000 (Mon, 24 Jun 2019)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2019-12839");

  script_name("OrangeHRM <= 4.3.1 Remote Code Execution (RCE) Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_orangehrm_detect.nasl");
  script_mandatory_keys("orangehrm/detected");

  script_tag(name:"summary", value:"OrangeHRM is prone to a remote code execution (RCE) vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The vulnerability exists due to an input validation error within
  admin/listMailConfiguration (txtSendmailPath parameter).");
  script_tag(name:"impact", value:"Successful exploitation would allow an authenticated attacker to
  execute arbitrary code on the target machine.");
  script_tag(name:"affected", value:"OrangeHRM through version 4.3.1.");
  script_tag(name:"solution", value:"Update to version 4.3.2.");

  script_xref(name:"URL", value:"https://ctrsec.io/index.php/2019/06/11/ace-orangehrm/");
  script_xref(name:"URL", value:"https://github.com/orangehrm/orangehrm/pull/528");

  exit(0);
}

CPE = "cpe:/a:orangehrm:orangehrm";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) ) exit( 0 );
version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "4.3.2" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "4.3.2", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
