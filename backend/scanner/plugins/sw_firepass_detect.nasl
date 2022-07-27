###############################################################################
# OpenVAS Vulnerability Test
# $Id: sw_firepass_detect.nasl 10906 2018-08-10 14:50:26Z cfischer $
#
# F5 Firepass Detection
#
# Authors:
# Christian Fischer <info@schutzwerk.com>
#
# Copyright:
# Copyright (C) 2015 SCHUTZWERK GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.111015");
  script_version("$Revision: 10906 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 16:50:26 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2015-04-17 08:00:00 +0100 (Fri, 17 Apr 2015)");
  script_name("F5 FirePass Detection");

  script_tag(name:"summary", value:"Detection of the installation and version
  of a F5 Firepass.

  The script sends HTTP GET requests and try to comfirm the F5 Firepass installation
  and version from the responses.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 SCHUTZWERK GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );

req = http_get( item:string( "/tunnel\r\n" ), port:port );
res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( res && "FirePass server could not handle the request" >< res )
{
  firepassVer = 'unknown';

  req = http_get( item:string( "/admin/" ), port:port );
  res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

  ver = eregmatch( pattern:"Version - FirePass ([0-9\.]+)", string:res );

  if( ver[1] ) firepassVer = ver[1];

  set_kb_item( name:string( "www/", port, "/firepass" ), value:firepassVer );
  set_kb_item( name:"firepass/installed",value:TRUE );

  cpe = build_cpe( value:firepassVer, exp:"([0-9a-z.]+)", base:"cpe:/h:f5:firepass:" );
  if( isnull( cpe ) )
    cpe = 'cpe:/h:f5:firepass';

  register_product( cpe:cpe, location:"/", port:port );

  log_message( data: build_detection_report( app:"F5 Firepass",
                                             version:firepassVer,
                                             install:"/",
                                             cpe:cpe,
                                             concluded:ver[0] ),
                                             port:port );
   exit( 0 );
}