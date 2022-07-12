###############################################################################
# OpenVAS Vulnerability Test
# $Id: linpha_detect.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# LinPHA Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100119");
  script_version("$Revision: 11885 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2009-04-10 19:06:18 +0200 (Fri, 10 Apr 2009)");

  script_name("LinPHA Detection");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detects the installed version of
  LinPHA, a photo/image archive/album/gallery written in PHP.

  This script sends HTTP GET request and try to get the version from the
  response, and sets the result in KB.");

  script_xref(name:"URL", value:"http://linpha.sourceforge.net");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

port = get_http_port( default:80 );
if( ! can_host_php( port:port ) ) exit( 0 );

foreach dir( make_list_unique( "/", "/linpha", "/image", "/album", cgi_dirs( port:port ) ) ) {
  install = dir;
  if( dir == "/" ) dir = "";

  buf = http_get_cache( item:dir + "/index.php", port:port );
  if( isnull( buf ) ) continue;

  if( (egrep( pattern:"LinPHA Version [0-9.]+", string:buf, icase:TRUE )
       && egrep (pattern:"The LinPHA developers", string:buf, icase:TRUE ) ) ||
      buf =~ "LinPHA  [0-9.]+" ) {

    vers = "unknown";

    version = eregmatch( string:buf, pattern:"LinPHA (Version)? ([0-9.]+)", icase:TRUE );
    if( ! isnull( version[2] ) )
      vers = version[2];

    set_kb_item( name:"linpha/detected", value:TRUE );

    cpe = build_cpe( value:vers, exp:"^([0-9.]+)", base:"cpe:/a:linpha:linpha:" );
    if (!cpe)
      cpe = "cpe:/a:linpha:linpha";

    register_product( cpe:cpe, location:install, port:port );

    log_message( data:build_detection_report( app:"LinPHA", version:vers, install:install, cpe:cpe,
                                              concluded:version[0] ),
                 port:port );
    exit( 0 );
  }
}

exit( 0 );
