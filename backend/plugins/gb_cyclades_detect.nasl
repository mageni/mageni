###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cyclades_detect.nasl 10902 2018-08-10 14:20:55Z cfischer $
#
# Cyclades Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.105068");
  script_version("$Revision: 10902 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 16:20:55 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2014-08-19 11:37:55 +0200 (Tue, 19 Aug 2014)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Cyclades Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"The script sends a connection request to the server and attempts
  to extract the version number from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

port = get_http_port( default:80 );

# Choose file to request based on what the remote host is supporting
if( can_host_asp( port:port ) && can_host_php( port:port ) ) {
  urls = make_list( "/home.asp", "/logon.php?redirect=index.php&nouser=1" );
} else if( can_host_asp( port:port ) ) {
  urls = make_list( "/home.asp" );
} else if( can_host_php( port:port ) ) {
  urls = make_list( "/logon.php?redirect=index.php&nouser=1" );
} else {
  exit( 0 );
}

foreach url( urls ) {

  buf = http_get_cache( item:url, port:port );

  if( "Welcome to the Cyclades" >!< buf ) continue;

  set_kb_item( name:"cyclades/installed", value:TRUE );
  CL = TRUE;
  install = url;

  if( 'class="is"' >< buf ) ts = TRUE;
  lines = split( buf, keep:FALSE );

  x = 0;
  f = 0;
  foreach line ( lines ) {
    x++;
    if( 'class="is"' >< line ) {
      f++;
      match = eregmatch( pattern:'<center>([^<]+)', string:line );
      if( ! isnull( match[1] ) ) info[f] = match[1];
    }

    else if( 'color="#003366"' >< line && ! ts ) {
      f++;
      match = eregmatch( pattern:'([^ <]+)', string:lines[x] );
      if( ! isnull( match[1] ) ) info[f] = match[1];
    }
  }
}

if( ! CL || ! info ) exit( 0 );

model = 'unknown';
vers  = 'unknown';

if( ! isnull( info[1] ) ) model = info[1];
if( ! isnull( info[2] ) ) host = info[2];
if( ! isnull( info[3] ) ) {
  version = eregmatch( pattern:'V_([^ ]+)', string: info[3] );
  if( ! isnull( version[1] ) ) vers = version[1];
}

set_kb_item( name:'cyclades/model', value:model );
set_kb_item( name:'cyclades/fw_version', value:vers );
set_kb_item( name:'cyclades/hostname', value:host );

cpe = 'cpe:/o:cyclades:' + tolower( model ) + ':' + tolower( vers );
register_and_report_os( os:"Cyclades " + model, cpe:cpe, banner_type:"HTTP banner", desc:"Cyclades Detection", runs_key:"unixoide" );

data = 'The remote host is a Cyclades-' + model + '.\nFirmware Version: ' + vers + '\n';
if( host ) data += 'Hostname: ' + host;

log_message( data:data, port:port );
exit( 0 );
