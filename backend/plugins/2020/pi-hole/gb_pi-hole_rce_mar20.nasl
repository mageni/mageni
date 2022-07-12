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

CPE = "cpe:/a:pi-hole:web";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108734");
  script_version("2020-03-30T08:21:10+0000");
  script_cve_id("CVE-2020-8816");
  script_tag(name:"last_modification", value:"2020-03-30 09:58:56 +0000 (Mon, 30 Mar 2020)");
  script_tag(name:"creation_date", value:"2020-03-30 07:42:25 +0000 (Mon, 30 Mar 2020)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_name("Pi-hole Ad-Blocker < 4.3.3 Remote Code Execution Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_pi-hole_detect.nasl");
  script_mandatory_keys("pi-hole/detected");

  script_tag(name:"summary", value:"The Pi-hole Ad-Blocker is prone to a remote code execution (RCE)
  vulnerability in the web interface.");

  script_tag(name:"insight", value:"The flaw exists because the application does not adequately validate
  input in the MAC address validator before reusing it in a shell command.");

  script_tag(name:"impact", value:"The RCE allows an authenticated user to execute arbitrary commands
  on the underlying server with the privileges of the local user running the service.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Pi-hole Ad-Blocker before version 4.3.3.");

  script_tag(name:"solution", value:"Update to version 4.3.3 or later.");

  script_xref(name:"URL", value:"https://github.com/pi-hole/AdminLTE/pull/1165");
  script_xref(name:"URL", value:"https://github.com/pi-hole/AdminLTE/releases/tag/v4.3.3");
  script_xref(name:"URL", value:"https://natedotred.wordpress.com/2020/03/28/cve-2020-8816-pi-hole-remote-code-execution/");

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

if( version_is_less( version:vers, test_version:"4.3.3" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"4.3.3", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
