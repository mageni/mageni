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
  script_oid("1.3.6.1.4.1.25623.1.0.113407");
  script_version("2019-06-11T10:55:09+0000");
  script_tag(name:"last_modification", value:"2019-06-11 10:55:09 +0000 (Tue, 11 Jun 2019)");
  script_tag(name:"creation_date", value:"2019-06-11 11:02:33 +0000 (Tue, 11 Jun 2019)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2019-11517");

  script_name("WampServer >= 3.1.3, <= 3.1.8 CSRF Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wampserver_detect.nasl");
  script_mandatory_keys("wampserver/installed");

  script_tag(name:"summary", value:"WampServer is prone to a cross-site request forgery (CSRF) vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The synchronizer pattern implemented in add_vhost.php as remediation of CVE-2018-8817
  is incomplete.");
  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to add and delete any vhosts
  without the consent of the owner.");
  script_tag(name:"affected", value:"WampServer versions 3.1.3 through 3.1.8.");
  script_tag(name:"solution", value:"Update to version 3.1.9.");

  script_xref(name:"URL", value:"https://seclists.org/bugtraq/2019/Jun/10");

  exit(0);
}

CPE = "cpe:/a:wampserver:wampserver";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) ) exit( 0 );
version = infos["version"];
location = infos["location"];

if( version_in_range( version: version, test_version: "3.1.3", test_version2: "3.1.8" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.1.9", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
