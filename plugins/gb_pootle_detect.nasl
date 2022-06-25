###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_pootle_detect.nasl 4356 2016-10-26 14:53:55Z cfi $
#
# Pootle Server Detection
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.108008");
  script_version("$Revision: 4356 $");
  script_tag(name:"last_modification", value:"$Date: 2016-10-26 16:53:55 +0200 (Wed, 26 Oct 2016) $");
  script_tag(name:"creation_date", value:"2016-10-26 14:47:00 +0200 (Wed, 26 Oct 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Pootle Server Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"The script sends a HTTP request to the server
  and attempts to extract the version from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("cpe.inc");

port = get_http_port( default:80 );

foreach dir( make_list_unique( "/", "/translate", "/pootle", cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" ) dir = "";

  url = dir + "/about/";

  buf = http_get_cache( item:url, port:port );

  if( buf =~ "HTTP/1.. 200" && (
      ">About this Pootle Server<" >< buf ||
      "<li>This Pootle Server</li>" >< buf ||
      "javascript:PTL.zoom.zoom" >< buf ||
      "<title>This Pootle Server" >< buf ) ) {

    version = 'unknown';

    # <p>Pootle 2.5.1-rc1 is powered by Translate Toolkit 1.11.0-rc1</p>
    # <p>Pootle 2.5.0 is powered by Translate Toolkit 1.10.0</p>
    # <p>Pootle 2.5.1.3 is powered by Translate Toolkit 1.13.0</p>
    ver = eregmatch( pattern:"<p>Pootle ([0-9.]+)(-([a-zA-Z]+)([0-9]+))? is powered", string:buf );
    if( ! isnull( ver[1] ) ) {
      version = ver[1];
      concludedUrl = report_vuln_url( port:port, url:url, url_only:TRUE );
      if( ver[2] ) {
        ver[2] = ereg_replace( pattern:"-", string:ver[2], replace:"." );
        version = ver[1] + ver[2];
      }
    }

    # CPE is not registered yet
    cpe = build_cpe( value:version, exp:"([0-9.a-zA-Z]+)", base:"cpe:/a:translatehouse:pootle:");
    if( isnull( cpe ) )
      cpe = 'cpe:/a:translatehouse:pootle';

    set_kb_item( name:"www/" + port + "/pootle_server", value:version );
    set_kb_item( name:"pootle_server/installed", value:TRUE );

    register_product( cpe:cpe, location:install, port:port );

    log_message( data: build_detection_report( app:"Pootle Server",
                                               version:version,
                                               install:install,
                                               cpe:cpe,
                                               concluded:ver[0],
                                               concludedUrl:concludedUrl ),
                                               port:port );
  }
}

exit( 0 );
