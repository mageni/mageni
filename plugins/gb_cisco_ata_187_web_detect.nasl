###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_ata_187_web_detect.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# Cisco ATA 187 Detection (HTTP)
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140084");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-12-01 13:31:46 +0100 (Thu, 01 Dec 2016)");
  script_name("Cisco ATA 187 Detection (HTTP)");

  script_tag(name:"summary", value:"This script performs HTTP based detection of Cisco ATA 187 devices");

  script_tag(name:"qod_type", value:"remote_banner");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

port = get_http_port( default:80 );

url = '/Device_Information.htm';
req = http_get( item:url, port:port );
buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( "<title>Cisco Systems, Inc.</title>" >!< buf || "Cisco ATA 187" >!< buf ) exit( 0 );

cpe = 'cpe:/o:cisco:ata_187_analog_telephone_adaptor_firmware';
set_kb_item( name:"cisco/ata187/detected", value:TRUE);

lines = split( buf );
vers = 'unknown';

for( i = 0; i < max_index( lines ); i++ )
{
  if( "SW_Version ID" >< lines[i] )
  {
   for( x = 0; x < 3; x++ )
   {
     # <td><p><b>SW_Version ID</b></p></td>
     # <td width=20 style='width:15.0pt;padding:0cm 0cm 0cm 0cm'></td>
     # <td><p><b>187.9-2-3-1
     # </b></p></td></tr>
     if( v = eregmatch( pattern:'>187.([0-9-]+)', string: lines[ i + x ]) )
     {
       if( ! isnull( v[1] ) )
       {
         vers = str_replace( string:v[1], find:"-", replace:'.' );
         cpe += ':' + vers;
       }
       break;
     }
   }
  }
}

register_product( cpe:cpe, location:"/", port:port, service:"www" );

report = build_detection_report( app:"Cisco ATA 187", version:vers, install:"/", cpe:cpe, concluded:v[0], concludedUrl:url );

log_message( port:port, data:report );
exit( 0 );

