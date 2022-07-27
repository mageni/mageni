# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
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

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.107613");
  script_version("2019-04-11T08:50:06+0000");
  script_tag(name:"last_modification", value:"2019-04-11 08:50:06 +0000 (Thu, 11 Apr 2019)");
  script_tag(name:"creation_date", value:"2019-03-11 16:46:07 +0100 (Mon, 11 Mar 2019)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"registry");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_name("NREL BEopt <= 2.8.0.0 Remote Code Execution Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_nrel_beopt_detect_win.nasl");
  script_mandatory_keys("nrel/beopt/win/detected");

  script_tag(name:"summary", value:"NREL BEopt is prone to a remote code execution (RCE) vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The vulnerability is caused due to the application loading libraries
  (sdl2.dll and libegl.dll) in an insecure manner.");
  script_tag(name:"impact", value:"This can be exploited to load arbitrary libraries by tricking a user
  into opening a related application file .BEopt located on a remote WebDAV or SMB share.");

  script_tag(name:"affected", value:"NREL BEopt versions through 2.8.0.0.");
  script_tag(name:"solution", value:"No known solution is available as of 11th April, 2019.
  Information regarding this issue will be updated once solution details are available.");
  script_xref(name:"URL", value:"https://www.zeroscience.mk/en/vulnerabilities/ZSL-2019-5513.php");

  exit(0);
}

CPE = "cpe:/a:nrel:beopt";

include( "host_details.inc" );
include( "version_func.inc" );

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);

vers = infos['version'];
path = infos['location'];

if(version_is_less_equal(version: vers, test_version: "2.8.0.0")) {
  report = report_fixed_ver(installed_version: vers, fixed_version: "None Available", install_path: path);
  security_message(data: report, port: 0);
  exit(0);
}

exit(99);
