###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hp_printer_66690.nasl 14185 2019-03-14 13:43:25Z cfischer $
#
# HP Officejet Pro X Printers, Certain Officejet Pro Printers, Remote Disclosure of Information
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2014 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105040");
  script_bugtraq_id(66690);
  script_cve_id("CVE-2014-0160");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_version("$Revision: 14185 $");

  script_name("HP Officejet Pro X Printers, Certain Officejet Pro Printers, Remote Disclosure of Information");

  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/531993");

  script_tag(name:"last_modification", value:"$Date: 2019-03-14 14:43:25 +0100 (Thu, 14 Mar 2019) $");
  script_tag(name:"creation_date", value:"2014-06-03 16:01:41 +0200 (Tue, 03 Jun 2014)");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("General");
  script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("gb_hp_printer_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("hp_fw_ver", "hp_model");

  script_tag(name:"impact", value:"An attacker can exploit these issues to gain access to sensitive
  information that may aid in further attacks.");

  script_tag(name:"vuldetect", value:"Check the firmware version.");

  script_tag(name:"solution", value:"Updates are available. Please see the references or vendor advisory
  for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"A potential security vulnerability has been identified in HP Officejet
  Pro X printers and in certain Officejet Pro printers running OpenSSL. This is the OpenSSL
  vulnerability known as 'Heartbleed' (CVE-2014-0160) which could be exploited remotely
  resulting in disclosure of information.");

  script_tag(name:"affected", value:"HP Officejet Pro X451dn < BNP1CN1409BR

HP Officejet Pro X451dw  < BWP1CN1409BR

HP Officejet Pro X551dw  < BZP1CN1409BR

HP Officejet Pro X476dn  < LNP1CN1409BR

HP Officejet Pro X476dw  < LWP1CN1409BR

HP Officejet Pro X576dw  < LZP1CN1409BR

HP Officejet Pro 276dw   < FRP1CN1416BR

HP Officejet Pro 251dw   < EVP1CN1416BR

HP Officejet Pro 8610    < FDP1CN1416AR

HP Officejet Pro 8615    < FDP1CN1416AR

HP Officejet Pro 8620    < FDP1CN1416AR

HP Officejet Pro 8625    < FDP1CN1416AR

HP Officejet Pro 8630    < FDP1CN1416AR

HP Officejet Pro 8640    < FDP1CN1416AR

HP Officejet Pro 8660    < FDP1CN1416AR");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

port = get_kb_item( "hp_printer/port" );
if( ! port ) port = 0;

fw_ver = get_kb_item( "hp_fw_ver" );
if( ! fw_ver ) exit( 0 );

model = get_kb_item( "hp_model" );
if( ! model ) exit( 0 );

if("Officejet Pro X451dn" >< model )       fixed_ver = 'BNP1CN1409BR';
else if( "Officejet Pro X451dw" >< model ) fixed_ver = 'BWP1CN1409BR';
else if( "Officejet Pro X551dw" >< model ) fixed_ver = 'BZP1CN1409BR';
else if( "Officejet Pro X476dn" >< model ) fixed_ver = 'LNP1CN1409BR';
else if( "Officejet Pro X476dw" >< model ) fixed_ver = 'LWP1CN1409BR';
else if( "Officejet Pro X576dw" >< model ) fixed_ver = 'LZP1CN1409BR';
else if( "Officejet Pro 276dw"  >< model ) fixed_ver = 'FRP1CN1416BR';
else if( "Officejet Pro 251dw"  >< model ) fixed_ver = 'EVP1CN1416BR';
else if( "Officejet Pro 8610"   >< model ) fixed_ver = 'FDP1CN1416AR';
else if( "Officejet Pro 8615"   >< model ) fixed_ver = 'FDP1CN1416AR';
else if( "Officejet Pro 8620"   >< model ) fixed_ver = 'FDP1CN1416AR';
else if( "Officejet Pro 8625"   >< model ) fixed_ver = 'FDP1CN1416AR';
else if( "Officejet Pro 8630"   >< model ) fixed_ver = 'FDP1CN1416AR';
else if( "Officejet Pro 8640"   >< model ) fixed_ver = 'FDP1CN1416AR';
else if( "Officejet Pro 8660"   >< model ) fixed_ver = 'FDP1CN1416AR';

if( ! fixed_ver ) exit( 0 );

fw_build = int( substr( fw_ver, 6, 9 ) );
fixed_build = int( substr( fixed_ver, 6, 9 ) );

if( fw_build < fixed_build )
{
  report = 'Detected Firmware: ' + fw_ver + '\nFixed Firmware:    ' + fixed_ver + '\n';
  security_message(port:port, data:report );
  exit( 0 );
}

exit( 99 );