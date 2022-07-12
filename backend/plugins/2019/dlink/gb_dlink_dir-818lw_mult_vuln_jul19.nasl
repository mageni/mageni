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
  script_oid("1.3.6.1.4.1.25623.1.0.113451");
  script_version("2019-08-01T07:22:04+0000");
  script_tag(name:"last_modification", value:"2019-08-01 07:22:04 +0000 (Thu, 01 Aug 2019)");
  script_tag(name:"creation_date", value:"2019-07-31 12:01:18 +0000 (Wed, 31 Jul 2019)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_cve_id("CVE-2019-13481", "CVE-2019-13482");
  script_bugtraq_id(109131);

  script_name("D-Link DIR-818LW <= 2.06b01 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_dlink_dir_detect.nasl");
  script_mandatory_keys("d-link/dir/fw_version");

  script_tag(name:"summary", value:"D-Link DIR-818LW devices are prone to multiple vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Following vulnerabilities exist:

  - There is a command injection in HNAP1 (exploitable with authentication)
    via shell metacharacters in the MTU field to SetWanSettings.

  - There is a command injection in HNAP1 (exploitable with authentication)
    via shell metacharacters in the Type field to SetWantSettings.");
  script_tag(name:"impact", value:"Successful exploitation would allow an authenticated attacker
  to gain complete control over the target device.");
  script_tag(name:"affected", value:"D-Link DIR-818LW through firmware version 2.06b01.");
  script_tag(name:"solution", value:"No known solution is available as of 31st July, 2019.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://github.com/TeamSeri0us/pocs/blob/master/iot/dlink/dir818-3.pdf");
  script_xref(name:"URL", value:"https://github.com/TeamSeri0us/pocs/blob/master/iot/dlink/dir818-4.pdf");

  exit(0);
}

CPE = "cpe:/o:d-link:dir-818lw_firmware";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! version = get_app_version( cpe: CPE, port: port ) ) exit( 0 );

if( version_is_less_equal( version: version, test_version: "2.06b01" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "None Available" );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
