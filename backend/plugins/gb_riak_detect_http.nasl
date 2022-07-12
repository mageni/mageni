###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_riak_detect_http.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# Basho Riak Detection (HTTP)
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
  script_oid("1.3.6.1.4.1.25623.1.0.105590");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-03-30 13:30:23 +0200 (Wed, 30 Mar 2016)");
  script_name("Basho Riak Detection (HTTP)");

  script_tag(name:"summary", value:"The script sends a connection request to the server and attempts to extract the version number from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 8098);
  script_mandatory_keys("MochiWeb/banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

port = get_http_port( default:8098 );

banner = get_http_banner( port:port );
if( "MochiWeb" >!< banner ) exit( 0 );

url = '/stats';
buf = http_get_cache( item:url, port:port );

if( buf !~ "HTTP/1\.. 200" || "riak_search_version" >!< buf ) exit( 0 );

b = split( buf, sep:'\r\n\r\n', keep:FALSE );
if( ! b[1] ) exit( 0 );

values = split( b[1], sep:",", keep:FALSE );

foreach v ( values )
{
  if( "riak_search_version" >< v )
  {
    version = eregmatch( pattern:'"riak_search_version":"([^"]+)"', string:v );
    if( ! isnull( version[1] ) ) vers = version[1];
  }

  val_rep += v + '\n';
}

cpe = "cpe:/a:basho:riak";

if( vers ) # for example 1.4.7-0-g2a44e2f while gb_riak_detect.nasl will report just 1.4.7.
  cpe += ':' + vers;
else
  vers = 'unknown';

register_product( cpe:cpe, location:"/", port:port, service:'www' );
set_kb_item( name:"riad/http/stats", value:val_rep );
set_kb_item( name:"riad/installed", value:TRUE );

report = build_detection_report( app:"Basho Riak", version:vers, install: '/',concluded:version[0],cpe:cpe, extra:'\nStats:' + val_rep + '\n' );

log_message( port:port, data:report );
exit( 0 );


