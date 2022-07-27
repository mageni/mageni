###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hp_ilo_56597.nasl 12175 2018-10-31 06:20:00Z ckuersteiner $
#
# HP Integrated Lights-Out Unspecified Information Disclosure Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.103783");
  script_bugtraq_id(56597);
  script_cve_id("CVE-2012-3271");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_version("$Revision: 12175 $");
  script_name("HP Integrated Lights-Out Unspecified Information Disclosure Vulnerability");
  script_tag(name:"last_modification", value:"$Date: 2018-10-31 07:20:00 +0100 (Wed, 31 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-09-10 18:14:19 +0200 (Tue, 10 Sep 2013)");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("ilo_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("HP_ILO/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/56597");
  script_xref(name:"URL", value:"http://www.hp.com");

  script_tag(name:"impact", value:"Remote attackers can exploit this issue to gain access to sensitive
information that may aid in further attacks.");

  script_tag(name:"vuldetect", value:"Check the firmware version.");

  script_tag(name:"insight", value:"Allows remote attackers to obtain sensitive information via unknown vectors.");

  script_tag(name:"solution", value:"Updates are available.");

  script_tag(name:"summary", value:"HP Integrated Lights-Out is prone to an unspecified information
disclosure vulnerability.");

  script_tag(name:"affected", value:"Integrated Lights-Out 3 (aka iLO3) with firmware before 1.50 and
Integrated Lights-Out 4 (aka iLO4) with firmware before 1.13");

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
  fix = "1.50";
else
  fix = "1.13";

if( version_is_less( version:fw_vers, test_version:fix ) ) {
  report = 'ILO Generation: ' + ilo_vers + '\nInstalled Firmware Version: ' + fw_vers + '\nFixed Firmware Version:     ' + fix + '\n';
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
