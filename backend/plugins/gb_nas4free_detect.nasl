###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_nas4free_detect.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# nas4free Detection
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105054");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"remote_banner");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-07-02 14:53:50 +0200 (Wed, 02 Jul 2014)");
  script_name("nas4free Detection");


  script_tag(name:"summary", value:"The script sends a connection request to the server and attempts
to detect nas4free from the reply.");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

include("host_details.inc");

port = get_http_port( default:80 );
if( ! can_host_php( port:port ) ) exit (0);

url = "/login.php";
buf = http_get_cache( item:url, port:port );
if( buf == NULL ) exit( 0 );

if( "The NAS4Free Project" >< buf && 'title="www.nas4free.org"' >< buf && "username" >< buf && "password" >< buf )
{
  install = "/";
  vers = "unknown";

  set_kb_item(name: string( "www/", port, "/nas4free" ), value: string( vers," under ",install ) );
  set_kb_item(name:"nas4free/installed",value:TRUE);

  cpe = 'cpe:/a:nas4free:nas4free';

  register_product( cpe:cpe, location:install, port:port );

  log_message( data: build_detection_report( app:"nas4free",
                                             version:vers,
                                             install:install,
                                             cpe:cpe ),
               port:port );
  exit( 0 );


}


exit(0);

