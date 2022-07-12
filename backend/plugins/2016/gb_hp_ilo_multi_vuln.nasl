###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hp_ilo_multi_vuln.nasl 14181 2019-03-14 12:59:41Z cfischer $
#
# HP Integrated Lights-Out Multiple Vulnerabilities
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106182");
  script_version("$Revision: 14181 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-14 13:59:41 +0100 (Thu, 14 Mar 2019) $");
  script_tag(name:"creation_date", value:"2016-08-18 10:47:20 +0700 (Thu, 18 Aug 2016)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2016-4375");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("HP Integrated Lights-Out Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("ilo_detect.nasl");
  script_mandatory_keys("HP_ILO/installed");

  script_tag(name:"summary", value:"HP Integrated Lights-Out is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Potential security vulnerabilities have been identified in HPE
  Integrated Lights Out. The vulnerabilities could lead to multiple remote vulnerabilities.");

  script_tag(name:"affected", value:"HPE Integrated Lights-Out 3 (iLO 3), Firmware for ProLiant G7 Servers
  prior to v1.88 and HPE Integrated Lights-Out 4 (iLO 4), prior to v2.44.");

  script_tag(name:"solution", value:"HPE has provided firmware updates to resolve this vulnerability. iLO 3
  version v1.88 or subsequent, iLO 4 version v2.44 or subsequent");

  script_xref(name:"URL", value:"https://h20564.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-c05236950");

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
  fix = "1.88";
else
  fix = "2.44";

if( version_is_less( version:fw_vers, test_version:fix ) ) {
  report = 'ILO Generation: ' + ilo_vers + '\nInstalled Firmware Version: ' + fw_vers + '\nFixed Firmware Version:     ' + fix + '\n';
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );