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
  script_oid("1.3.6.1.4.1.25623.1.0.113551");
  script_version("2019-10-28T11:05:31+0000");
  script_tag(name:"last_modification", value:"2019-10-28 11:05:31 +0000 (Mon, 28 Oct 2019)");
  script_tag(name:"creation_date", value:"2019-10-28 11:39:57 +0000 (Mon, 28 Oct 2019)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_cve_id("CVE-2019-17177", "CVE-2019-17178");

  script_name("FreeRDP <= 2.0.0-rc4 Memory Leak Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_freerdp_detect_lin.nasl");
  script_mandatory_keys("FreeRDP/Linux/Ver");

  script_tag(name:"summary", value:"FreeRDP is prone to a memory leak vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The vulnerability exists because a supplied realloc pointer
  is also used for a realloc return value.");
  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to exhaust
  the targets system's resources and subsequently cause a slowdown or crash.");
  script_tag(name:"affected", value:"FreeRDP through version 2.0.0-rc4.");
  script_tag(name:"solution", value:"No known solution is available as of 28th October, 2019.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://github.com/FreeRDP/FreeRDP/issues/5645");
  script_xref(name:"URL", value:"https://github.com/akallabeth/FreeRDP/commit/fc80ab45621bd966f70594c0b7393ec005a94007");

  exit(0);
}

CPE = "cpe:/a:freerdp_project:freerdp";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE ) ) exit( 0 );
version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "2.0.0" ) ||
    ( version =~ "^2\.0\.0-rc" && version_is_less_equal( version: version, test_version: "2.0.0-rc4" ) ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "None Available", install_path: location );
  security_message( data: report, port: 0 );
  exit( 0 );
}

exit( 99 );
