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

CPE = "cpe:/a:teamviewer:teamviewer";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107736");
  script_version("2019-10-26T12:37:12+0000");
  script_cve_id("CVE-2019-18196");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-10-26 12:37:12 +0000 (Sat, 26 Oct 2019)");
  script_tag(name:"creation_date", value:"2019-10-26 14:04:11 +0200 (Sat, 26 Oct 2019)");

  script_name("TeamViewer DLL side loading Vulnerability - Oct19 (Windows)");

  script_tag(name:"summary", value:"The host is installed with TeamViewer
  Premium is prone to a dll-side-loading vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A DLL side loading vulnerability in the Windows Service in TeamViewer
  on Windows could allow an attacker to perform code execution on a target system via a service restart
  where the DLL was previously installed with administrative privileges.

  Exploitation requires that an attacker be able to create a new file in the TeamViewer application
  directory, directory permissions restrict that by default.");

  script_tag(name:"affected", value:"TeamViewer versions through 11.0.133222, 12.0.181268, 13.2.36215
  and 14.6.4835 on Windows.");

  script_tag(name:"solution", value:"Update to TeamViewer version 11.0.214397, 12.0.214399, 13.2.36216,
  14.7.1965 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://community.teamviewer.com/t5/Announcements/Security-bulletin-CVE-2019-18196/td-p/74564");

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_teamviewer_win_detect.nasl");
  script_mandatory_keys("teamviewer/Ver");
  exit(0);
}


include( "host_details.inc" );
include( "version_func.inc" );

if( ! infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version:version, test_version:"11.0.214397" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"11.0.214397", install_path:location );
  security_message( data:report, port:0 );
  exit( 0 );
}
else if( version =~ "^12\.0" && version_is_less( version:version, test_version:"12.0.214399" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"12.0.214399", install_path:location );
  security_message( data:report, port:0 );
  exit( 0 );
}
else if( version =~ "^13\.[0-2]" && version_is_less( version:version, test_version:"13.2.36216" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"13.2.36216", install_path:location );
  security_message( data:report, port:0 );
  exit( 0 );
}
else if( version =~ "^14\.[0-7]" && version_is_less( version:version, test_version:"14.7.1965" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"14.7.1965", install_path:location );
  security_message( data:report, port:0 );
  exit( 0 );
}

exit( 99 );
