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

CPE = "cpe:/a:pihole:web";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108588");
  script_version("2019-05-27T06:43:57+0000");
  script_tag(name:"last_modification", value:"2019-05-27 06:43:57 +0000 (Mon, 27 May 2019)");
  script_tag(name:"creation_date", value:"2019-05-25 14:17:45 +0000 (Sat, 25 May 2019)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_name("Pi-hole Ad-Blocker < 4.3 Remote Code Execution Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_pihole_detect.nasl");
  script_mandatory_keys("pi-hole/detected");

  script_tag(name:"summary", value:"The Pi-hole Ad-Blocker is prone to a remote code execution vulnerability
  in the web interface.");

  script_tag(name:"insight", value:"A remote code execution could have been triggered by activating some list
  (adding or removing white/blacklist entries) via api.php by an authenticated user.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Pi-hole Ad-Blocker before version 4.3.");

  script_tag(name:"solution", value:"Update to version 4.3 or later.");

  script_xref(name:"URL", value:"https://pi-hole.net/2019/05/18/pi-hole-4-3-now-available/");
  script_xref(name:"URL", value:"https://github.com/pi-hole/AdminLTE/releases/tag/v4.3");
  script_xref(name:"URL", value:"https://github.com/pi-hole/AdminLTE/pull/921");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

vers = infos["version"];
path = infos["location"];

if( version_is_less( version:vers, test_version:"4.3" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"4.3", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );