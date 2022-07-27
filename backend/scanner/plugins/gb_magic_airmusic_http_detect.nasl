# Copyright (C) 2019 Greenbone Networks GmbH
#
# SPDX-License-Identifier: GPL-2.0-or-later
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108650");
  script_version("2019-09-18T13:31:29+0000");
  script_tag(name:"last_modification", value:"2019-09-18 13:31:29 +0000 (Wed, 18 Sep 2019)");
  script_tag(name:"creation_date", value:"2019-09-18 12:41:49 +0000 (Wed, 18 Sep 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Magic AirMusic Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "httpver.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"The script sends a HTTP request to the remote host and attempts
  to detect the presence of a Magic AirMusic device.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

port = get_http_port( default:80 );

buf = http_get_cache( item:"/", port:port );
if( ! buf )
  exit( 0 );

found = 0;

if( "erver: magic iradio" >< buf )
  found++;

if( "<title>AirMusic</title>" >< buf )
  found++;

if( "SetDevName('AirMusic','" >< buf )
  found++;

if( "SWDisp('AirMusic','" >< buf )
  found++;

if( egrep( string:buf, pattern:'id="(wifi|inp|unfold|fold|sw|swfold|swunfold)_AirMusic"', icase:FALSE ) )
  found++;

if( found < 2 )
  exit( 0 );

version = "unknown";

set_kb_item( name:"magic/airmusic/detected", value:TRUE );
cpe = "cpe:/a:magic:airmusic";

register_product( cpe:cpe, location:"/", port:port, service:"www" );

log_message( data:build_detection_report( app:"Magic AirMusic",
                                          version:version,
                                          install:"/",
                                          cpe:cpe ),
             port:port );

exit( 0 );
