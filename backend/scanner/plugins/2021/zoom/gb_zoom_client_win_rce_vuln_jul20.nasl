# Copyright (C) 2021 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
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

CPE = "cpe:/a:zoom:zoom";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.117738");
  script_version("2021-10-19T12:51:47+0000");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2021-10-20 10:23:51 +0000 (Wed, 20 Oct 2021)");
  script_tag(name:"creation_date", value:"2021-10-19 12:25:06 +0000 (Tue, 19 Oct 2021)");

  script_name("Zoom Client < 5.1.3 RCE Vulnerability (Jul 2020) - Windows");

  script_tag(name:"summary", value:"The Zoom Client is prone to a remote code execution (RCE)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability allows a remote attacker to execute arbitrary
  code on victim's computer where Zoom Client for Windows is installed by getting the user to
  perform some typical action such as opening a document file. No security warning is shown to the
  user in the course of attack.");

  script_tag(name:"affected", value:"Zoom Client versions prior to 5.1.3 on Windows.");

  script_tag(name:"solution", value:"Update to version 5.1.3 or later.

  Note: The update information is based on the information provided by a 3rdparty article linked in
  the references. No official information is currently available.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_zoom_client_smb_login_detect.nasl");
  script_mandatory_keys("zoom/client/win/detected");

  script_xref(name:"URL", value:"https://blog.0patch.com/2020/07/remote-code-execution-vulnerability-in.html");
  script_xref(name:"URL", value:"https://thehackernews.com/2020/07/zoom-windows-security.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ) )
  exit( 0 );

vers = infos["version"];
path = infos["location"];

if( version_is_less( version:vers, test_version:"5.1.3" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"5.1.3", install_path:path );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );