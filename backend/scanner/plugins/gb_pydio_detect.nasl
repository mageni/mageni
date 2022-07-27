###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_pydio_detect.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# Pydio Detection
#
# Authors:
# Jan Philipp Schulte <jan.schulte@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113003");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-09-27 12:06:59 +0200 (Wed, 27 Sep 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Pydio Detection");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_tag(name:"summary", value:"This host is running Pydio, a file explorer
for remotely managing files on a web server.");
  script_xref(name:"URL", value:"https://pydio.com/de");
  exit(0);
}

include( "http_func.inc" );
include( "http_keepalive.inc" );
include( "host_details.inc" );
include( "cpe.inc" );

port = get_http_port( default: 80 );

if( !can_host_php(port: port ) )
  exit( 0 );

foreach dir( make_list_unique( "/pydio", cgi_dirs( port: port ) ) ) {
 install = dir;
 if( dir == "/" ) dir = "";
 url = dir + "/index.php?get_action=get_boot_conf";
 req = http_get( item: url, port: port );
 buf = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );

 if( buf == NULL ) continue;

 if( egrep( pattern: '"ajxpVersion"', string: buf ) )
 {
    version_number = string("unknown");
    version = eregmatch( string: buf, pattern: '"ajxpVersion":"([0-9.]+)"', icase: TRUE );

    if ( !isnull( version[1] ) ) {
       version_number = chomp( version[1] );
    }

    tmp_version = version_number + " under " + install;
    set_kb_item( name: "www/" + port + "/pydio", value: tmp_version );
    set_kb_item( name: "pydio/installed", value: TRUE );

    cpe = build_cpe( value: version_number, exp: "([0-9.]+)", base: "cpe:/a:pydio:pydio:" );
    if( isnull( cpe ) )
      cpe = 'cpe:/a:pydio:pydio';
    register_product( cpe: cpe, location: install, port: port );

    log_message( data:build_detection_report( app: "Pydio",
                                              version: version_number,
                                              install: install,
                                              cpe: cpe,
                                              concludedUrl: url,
                                              concluded: version[0] ),
                                              port: port );
    exit( 0 );
  }
}

exit( 0 );
