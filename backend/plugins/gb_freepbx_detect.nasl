###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_freepbx_detect.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# FreePBX Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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
  script_oid("1.3.6.1.4.1.25623.1.0.100889");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2010-11-03 12:47:25 +0100 (Wed, 03 Nov 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("FreePBX Detection");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"The script sends a connection request to the server and attempts to
 extract the version number from the reply.");

  script_xref(name:"URL", value:"http://www.freepbx.org/");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

port = get_http_port( default:80 );
if( ! can_host_php( port:port ) ) exit (0 );

foreach dir( make_list_unique( "/freepbx", cgi_dirs( port:port ) ) ) {

 install = dir;
 if( dir == "/" ) dir = "";
 url = dir + "/admin/config.php";
 buf = http_get_cache( item:url, port:port );
 if( buf == NULL ) continue;

 if( "<title>FreePBX" >< buf && '<div id="version"><a href="http://www.freepbx.org" target="_blank">FreePBX' )
 {
    vers = string("unknown");
    version = eregmatch( string: buf, pattern: "FreePBX</a> ([0-9.]+) on <a",icase:TRUE );

    if ( ! isnull( version[1] ) )
       vers = chomp( version[1] );
    else
      version = eregmatch( string: buf, pattern:"freepbx_version=([0-9.]+)",icase:TRUE );

    if ( ! isnull(version[1] ) )
      vers = chomp( version[1] );
    else
     version = eregmatch( string: buf, pattern:'FreePBX ([0-9.]+) is licensed', icase:TRUE );

    if ( ! isnull(version[1] ) )
      vers = chomp( version[1] );

    set_kb_item(name: string("www/", port, "/freepbx"), value: string(vers," under ",install));
    set_kb_item(name:"freepbx/installed",value:TRUE);

    cpe = build_cpe(value:vers, exp:"^([0-9.]+)", base:"cpe:/a:freepbx:freepbx:");
    if( isnull( cpe ) )
      cpe = 'cpe:/a:freepbx:freepbx';

    register_product( cpe:cpe, location:install, port:port);

    log_message( data: build_detection_report( app:"FreePBX",
                                               version:vers,
                                               install:install,
                                               cpe:cpe,
                                               concluded: version[0]),
                 port:port );
  }
}

exit(0);
