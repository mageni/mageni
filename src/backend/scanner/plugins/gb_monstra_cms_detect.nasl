###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_monstra_cms_detect.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# Monstra CMS Detection
#
# Authors:
# Jan Philipp Schulte <jan.schulte@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, https://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113203");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-05-29 15:42:35 +0200 (Tue, 29 May 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Monstra CMS Detection");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Monstra CMS Product detection.");

  script_xref(name:"URL", value:"http://monstra.org/");

  exit(0);
}

include( "host_details.inc" );
include( "http_func.inc" );
include( "http_keepalive.inc" );
include( "cpe.inc" );

port = get_http_port( default: 80 );

foreach dir( make_list_unique( "/", "/monstra", cgi_dirs( port: port ) ) ) {
  location = dir;
  if( dir == "/" )
    dir = "";

  buf = http_get_cache( item: dir + "/", port: port );

  if( '<a href="http://monstra.org" target="_blank">Monstra</a>' >< buf || '<meta name="generator" content="Powered by Monstra' >< buf ) {
    set_kb_item( name: "monstra_cms/detected", value: TRUE );
    version = "unknown";

    vers = eregmatch( string: buf, pattern: '<a href="http://monstra.org" target="_blank">Monstra</a>[ ]{0,}([0-9.]+)[ ]{0,}</div>' );
    if( ! isnull( vers[1] ) ){
      version = vers[1];
    }

    set_kb_item( name: "monstra_cms/version", value: version );

    register_and_report_cpe( app: "Monstra CMS",
                             ver: version,
                             concluded: vers[0],
                             base: "cpe:/a:monstra:monstra:",
                             expr: "([0-9.]+)",
                             insloc: location,
                             regPort: port,
                             conclUrl: location );
    exit( 0 );
  }
}

exit( 0 );
