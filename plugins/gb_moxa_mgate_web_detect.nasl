###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_moxa_mgate_web_detect.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# Moxa MGate Detection (HTTP)
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
  script_oid("1.3.6.1.4.1.25623.1.0.105821");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-07-25 12:58:51 +0200 (Mon, 25 Jul 2016)");
  script_name("Moxa MGate Detection (HTTP)");

  script_tag(name:"summary", value:"This script performs HTTP based detection of Moxa MGate");

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

url = '/Overview.html';
req = http_get( item:url, port:port );
buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( buf !~ '>Welcome to MGate.*web console' || "<title>Overview</title>" >!< buf ) exit( 0 );

buf = str_replace( string:buf, find:"&nbsp;", replace:" " );

lines = split( buf );

cpe = 'cpe:/a:moxa:mgate';
version = "unknown";

for( i = 0; i < max_index( lines ); i++ )
{
  if( ">Model Name<" >< lines[i] )
  {
    mod = eregmatch( pattern:'>MGate ([^<]+)<', string:lines[i+1]);
    if( ! isnull( mod[1] ) )
    {
      model = mod[1];
      replace_kb_item( name:"moxa/mgate/model", value:model );
    }
  }

  if( ">Firmware version<" >< lines[i] )
  {
    vb = eregmatch( pattern:'>([0-9.]+[^ ]+) Build ([0-9]+[^< ]+)<', string:lines[i+1]);
    if( ! isnull( vb[1] ) )
    {
      version = vb[1];
      replace_kb_item( name:"moxa/mgate/version", value:version );
      cpe += ':' + version;
    }

    if( ! isnull( vb[2] ) )
    {
      build = vb[2];
      replace_kb_item( name:"moxa/mgate/build", value:build );
    }
  }
}

set_kb_item( name:'moxa/mgate/installed', value:TRUE );
register_product( cpe:cpe, location:"/", port:port, service:'www' );

report = 'Moxa MGate web console is running at this port.\n\n' +
         'Version: ' + version + '\n' +
         'CPE:     ' + cpe + '\n';

if( build )  report += 'Build    ' + build + '\n';
if( model )  report += 'Model:   ' + model + '\n';;

log_message( port:port, data:report );

exit(0);

