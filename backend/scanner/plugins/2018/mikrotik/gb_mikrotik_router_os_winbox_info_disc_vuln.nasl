###############################################################################
# OpenVAS Vulnerability Test
#
# Mikrotik RouterOS 'Winbox Service' Information Disclosure Vulnerability
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/o:mikrotik:routeros";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813155");
  script_version("2019-05-17T10:45:27+0000");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2018-04-25 11:34:56 +0530 (Wed, 25 Apr 2018)");

  script_cve_id("CVE-2018-14847");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Mikrotik RouterOS 'Winbox Service' Information Disclosure Vulnerability");

  script_tag(name:"summary", value:"This host is running Mikrotik RouterOS and is prone to information disclosure
vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an error in the winbox service of routeros which allows
remote users to download a user database file without successful authentication.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote attacker to connect to the WinBox
port and download a user database file. The remote user can then log in and take control of the router.");

  script_tag(name:"affected", value:"MikroTik Router OS versions 6.29 through 6.42, 6.43rcx prior to 6.43rc4");

  script_tag(name:"solution", value:"Upgrade to MikroTik Router OS version 6.42.1 or 6.43rc4 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://forum.mikrotik.com/viewtopic.php?t=133533");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_mikrotik_router_routeros_consolidation.nasl");
  script_mandatory_keys("mikrotik/detected");
  exit(0);
}

include( "host_details.inc" );
include( "version_func.inc" );

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE) ) exit(0);
mikVer = infos['version'];
mikPath = infos['location'];

if (version_in_range(version:mikVer, test_version:"6.29", test_version2:"6.42")){
  fix = "6.42.1";
} else if (mikVer == "6.43rc1" || mikVer == "6.43rc2" || mikVer == "6.43rc3"){
  fix = "6.43rc4";
}

if (fix) {
  report = report_fixed_ver(installed_version:mikVer, fixed_version:fix, install_path:mikPath);
  security_message( data: report, port: 0);
  exit( 0 );
}

exit(0);
