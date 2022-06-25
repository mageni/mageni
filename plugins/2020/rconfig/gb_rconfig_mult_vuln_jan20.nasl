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
  script_oid("1.3.6.1.4.1.25623.1.0.113621");
  script_version("2020-01-09T09:49:23+0000");
  script_tag(name:"last_modification", value:"2020-01-09 09:49:23 +0000 (Thu, 09 Jan 2020)");
  script_tag(name:"creation_date", value:"2020-01-09 09:38:07 +0000 (Thu, 09 Jan 2020)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_cve_id("CVE-2019-19509", "CVE-2019-19585");

  script_name("rConfig <= 3.9.3 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_rconfig_detect.nasl");
  script_mandatory_keys("rconfig/detected");

  script_tag(name:"summary", value:"rConfig is prone to multiple vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - A remote authenticated user can directly execute system commands by sending a GET request
    to ajaxArchiveFiles.php because the path parameter is passed to the exec function without filtering.

  - The install script updates the /etc/sudoers file for rConfig specific tasks. After an
    rConfig specific Apache configuration update, Apache has high privileges for some binaries.
    This can be exploited by an attacker to bypass local security restrictions.");
  script_tag(name:"impact", value:"Successful exploitation would allow an authenticated attacker to gain complete
  control over the target system.");
  script_tag(name:"affected", value:"rConfig through version 3.9.3.");
  script_tag(name:"solution", value:"No known solution is available as of 09th January, 2020.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://github.com/v1k1ngfr/exploits-rconfig/blob/master/rconfig_lpe.sh");
  script_xref(name:"URL", value:"https://github.com/v1k1ngfr/exploits-rconfig/blob/master/rconfig_CVE-2019-19509.py");

  exit(0);
}

CPE = "cpe:/a:rconfig:rconfig";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) ) exit( 0 );
version = infos["version"];
location = infos["location"];

if( version_is_less_equal( version: version, test_version: "3.9.3" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "None", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
