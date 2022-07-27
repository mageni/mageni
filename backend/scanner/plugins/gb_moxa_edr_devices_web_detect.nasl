###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_moxa_edr_devices_web_detect.nasl 10896 2018-08-10 13:24:05Z cfischer $
#
# Moxa EDR Detection
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140015");
  script_version("$Revision: 10896 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 15:24:05 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2016-10-25 10:43:45 +0200 (Tue, 25 Oct 2016)");
  script_name("Moxa EDR Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"This scriptperforms HTTP based detection of Moxa EDR devices.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

port = get_http_port( default:80 );
if( ! can_host_asp( port:port ) ) exit( 0 );

buf = http_get_cache( port:port, item:"/Login.asp" );

if( ! buf || "<TITLE>Moxa EDR</TITLE>" >!< buf ) exit( 0 );

cpe = 'cpe:/h:moxa:edr';

set_kb_item( name:"moxa_edr/detected", value:TRUE );

if( "Industrial Secure Router" >< buf || "var ProjectModel" >< buf ) {
  if( "var ProjectModel" >< buf ) {
    mn = eregmatch( pattern:'var ProjectModel = ([0-9]+);', string:buf );
    if( ! isnull( mn[1] ) ) {
      typ = mn[1];

      if( typ == 1 )
        mod = 'G903';
      else if( typ  == 2 )
         mod = 'G902';
      else if( typ  == 3 )
          mod = '810';

      cpe += '-' + mod;
      model = 'EDR-' + mod;
      set_kb_item( name:"moxa_edr/model", value:model );
    }
  } else {
    mod = eregmatch( pattern:"var Model(Nmae|Name) = '(EDR-[^']+)';", string:buf );
    if( ! isnull( mod[1] ) ) {
      model = mod[1];
      set_kb_item( name:"moxa_edr/model", value:model );
      cpe_mod = split( model, sep:'-', keep:FALSE );
      if( ! isnull( cpe_mod[1] ) )
      {
        cpe_model = cpe_mod[1];
        cpe += '-' + cpe_model;
      }
    }
  }
} else if( "EtherDevice Secure Router" >< buf ) {
  lines = split( buf );
  x = 0;
  foreach line ( lines ) {
    x++;
    if( "Moxa EtherDevice Secure Router" >< line ) {
      for( i = 0; i < 10; i++ ) {
        if( "EDR-" >< lines[ x + i ] ) {
          mod = eregmatch( pattern:'(EDR-[^ <]+)', string:lines[ x + i ] );
          if( ! isnull( mod[1] ) ) {
            model = mod[1];
            set_kb_item( name:"moxa_edr/model", value:model );
            cpe_mod = split( model, sep:'-', keep:FALSE );
            if( ! isnull( cpe_mod[1] ) ) {
              cpe_model = cpe_mod[1];
              cpe += '-' + cpe_model;
            }
          }
        }
      }
    }
  }
}

register_product( cpe:cpe, location:"/", port:port, service:"www" );

report = 'The remote Host is a Moxa EDR device.\nCPE: ' + cpe;

if( model ) report += '\nModel: ' + model;;

log_message( port:port, data:report );
exit( 0 );

