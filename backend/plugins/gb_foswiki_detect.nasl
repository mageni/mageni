###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_foswiki_detect.nasl 8141 2017-12-15 12:43:22Z cfischer $
#
# Foswiki Version Detection
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.800612");
  script_version("$Revision: 8141 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-15 13:43:22 +0100 (Fri, 15 Dec 2017) $");
  script_tag(name:"creation_date", value:"2009-05-11 08:41:11 +0200 (Mon, 11 May 2009)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Foswiki Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detection of Foswiki.

  The script sends a connection request to the server and attempts to
  extract the version number from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

port = get_http_port( default:80 );

foreach dir( make_list_unique( "/", "/foswiki", "/wiki", cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" ) dir = "";

  req = http_get( item:dir + "/Main/WebHome", port:port );
  res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

  if( "Powered by Foswiki" >!< res ) {
    req = http_get( item:dir + "/bin/view/foswiki/WebHome", port:port );
    res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );
  }

  if( res =~ "HTTP/1.. 200" && "Powered by Foswiki" >< res ) {

    version = "unknown";

    vers = eregmatch( pattern:"Foswiki-([0-9.]+)(,|</strong>)", string:res );
    if( ! isnull( vers[1] ) ) {
      version = vers[1];
    } else {
      vers = eregmatch( pattern:"Foswiki version <strong>v([0-9.]+)</strong>", string:res );
      if( ! isnull( vers[1] ) ) version = vers[1];
    }

    tmp_version = version + " under " + install;
    set_kb_item( name:"www/" + port + "/Foswiki", value:tmp_version );
    set_kb_item( name:"Foswiki/installed", value:TRUE );

    cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:foswiki:foswiki:" );
    if( isnull( cpe ) )
      cpe = 'cpe:/a:foswiki:foswiki';

    register_product( cpe:cpe, location:install, port:port );

    log_message( data:build_detection_report( app:"Foswiki",
                                              version:version,
                                              install:install,
                                              cpe:cpe,
                                              concluded:vers[0] ),
                                              port:port );
  }
}

exit(0);