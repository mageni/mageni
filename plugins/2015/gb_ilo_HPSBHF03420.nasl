###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ilo_HPSBHF03420.nasl 12175 2018-10-31 06:20:00Z ckuersteiner $
#
# HP Integrated Lights-Out 3 and 4 Remote Denial of Service
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2015 Greenbone Networks GmbH
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
###############################################################################

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105392");
  script_cve_id("CVE-2015-5435");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_version("$Revision: 12175 $");

  script_name("HP Integrated Lights-Out 3 and 4 Remote Denial of Service");

  script_tag(name:"last_modification", value:"$Date: 2018-10-31 07:20:00 +0100 (Wed, 31 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-10-01 14:58:10 +0200 (Thu, 01 Oct 2015)");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("ilo_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("HP_ILO/installed");

  script_xref(name:"URL", value:"http://h20564.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-c04785857");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See vendor advisory for a solution");

  script_tag(name:"summary", value:"A potential security vulnerability has been identified with HP Integrated
Lights-Out 3 and 4 (iLO 3, iLO 4). The vulnerability could be exploited remotely resulting in Denial of Service
(DoS).");

  script_tag(name:"affected", value:"HP Integrated Lights-Out 3 (iLO 3) prior to firmware version 1.85 HP
Integrated Lights-Out 4 (iLO 4) prior to firmware version 2.22");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list( "cpe:/o:hp:integrated_lights-out_3_firmware", "cpe:/o:hp:integrated_lights-out_4_firmware" );
if( ! infos = get_all_app_ports_from_list( cpe_list:cpe_list ) ) exit( 0 );
cpe  = infos['cpe'];
port = infos['port'];
if( ! fw_vers = get_app_version( cpe:cpe, port:port ) ) exit( 0 );

ilo_vers = get_kb_item( "www/" + port + "/HP_ILO/ilo_version" );
if( ilo_vers !~ "^(3|4)$" ) exit( 99 );

if( int( ilo_vers ) == 3 )
  fix = "1.85";
else
  fix = "2.22";

if( version_is_less( version:fw_vers, test_version:fix ) ) {
  report = 'ILO Generation: ' + ilo_vers + '\nInstalled Firmware Version: ' + fw_vers + '\nFixed Firmware Version:     ' + fix + '\n';
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
