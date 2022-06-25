###############################################################################
# OpenVAS Vulnerability Test
#
# Cisco ATA Detection (HTTP)
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH
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
  script_version("2020-07-31T08:46:05+0000");
  script_tag(name:"last_modification", value:"2020-08-03 11:16:30 +0000 (Mon, 03 Aug 2020)");
  script_tag(name:"creation_date", value:"2016-12-01 13:31:46 +0100 (Thu, 01 Dec 2016)");

  script_name("Cisco ATA Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of Cisco Analog Telephone Adapter (ATA) devices.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

port = http_get_port( default:80 );

url = "/DeviceInfo";
buf = http_get_cache( item:url, port:port );

if( "Change Configuration" >!< buf || ">Cisco ATA" >!< buf ) {
  url  = "/Device_Information.htm";
  buf = http_get_cache( item:url, port:port );
  if( "<title>Cisco Systems, Inc.</title>" >!< buf || "Cisco ATA" >!< buf )
    exit( 0 );
}

version = "unknown";
model = "unknown";

set_kb_item( name:"cisco/ata/detected", value:TRUE );
set_kb_item( name:"cisco/ata/http/detected", value:TRUE );
set_kb_item( name:"cisco/ata/http/port", value:port );
set_kb_item( name:"cisco/ata/http/" + port + "/concludedUrl", value:http_report_vuln_url( port:port, url:url, url_only:TRUE ));

# <p><b><font color=#FFFFFF size=5>Cisco ATA 186 (SIP)</font></center></td>
mod = eregmatch( pattern:">Cisco ATA ([0-9]+)", string:buf );
if( ! isnull( mod[1] ) )
  model = mod[1];

# <tr><td><b>S/W Version</td><td>3.02.00(041111A)</td>
vers = eregmatch( pattern:"S/W Version<[^0-9]+([0-9.]+)[^<]+", string:buf );
if( ! isnull( vers[1] ) ) {
  version = vers[1];
  set_kb_item( name:"cisco/ata/http/" + port + "/concluded", value:vers[0] );
} else {
  lines = split( buf );

  for( i = 0; i < max_index( lines ); i++ ) {
    if( "SW_Version ID" >< lines[i] ) {
     for( x = 0; x < 3; x++ ) {
       # <td><p><b>SW_Version ID</b></p></td>
       # <td width=20 style='width:15.0pt;padding:0cm 0cm 0cm 0cm'></td>
       # <td><p><b>187.9-2-3-1
       # </b></p></td></tr>
       if( vers = eregmatch( pattern:'>[0-9]{3}.([0-9-]+)', string: lines[ i + x ]) ) {
         if( ! isnull( vers[1] ) ) {
           version = str_replace( string:vers[1], find:"-", replace:"." );
           set_kb_item( name:"cisco/ata/http/" + port + "/concluded", value:vers[0] );
         }
         break;
       }
     }
    }
  }
}

set_kb_item( name:"cisco/ata/http/" + port + "/model", value:model );
set_kb_item( name:"cisco/ata/http/" + port + "/version", value:version );

exit( 0 );
