###############################################################################
# OpenVAS Vulnerability Test
#
# dotProject Version Detection
#
# Authors:
# Nikita MR <rnikita@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.800564");
  script_version("2019-05-14T12:12:41+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-05-14 12:12:41 +0000 (Tue, 14 May 2019)");
  script_tag(name:"creation_date", value:"2009-05-07 14:39:04 +0200 (Thu, 07 May 2009)");
  script_name("dotProject Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"This script finds the installed version
  of dotProject and saves the result in KB.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

port = get_http_port( default:80 );
if( ! can_host_php( port:port ) ) exit( 0 );

foreach dir( make_list_unique( "/dotproject", "/dotProject", "/Dotproject", cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" ) dir = "";

  res = http_get_cache( item:dir + "/index.php", port:port );

  # TODO: This is still really weak...
  if( res =~ "HTTP/1\.. 200" && "dotProject" >< res ) {

    version = eregmatch( pattern:"Version ([0-9.]+)(rc[0-9])?", string:res );
    if( version[1] != NULL ) {
      if( version[2] != NULL ) {
        vers = version[1] + "." + version[2];
      } else {
        vers = version[1];
      }

      tmp_version = vers + " under " + install;
      set_kb_item( name:"www/" + port + "/dotProject", value:tmp_version );
      set_kb_item( name:"dotproject/detected", value:TRUE );

      cpe = build_cpe( value:vers, exp:"^([0-9.]+\.[0-9])\.?([a-z0-9]+)?", base:"cpe:/a:dotproject:dotproject:" );
      if( cpe ) {
        register_product( cpe:cpe, location:install, port:port );
        log_message( data:build_detection_report( app:"dotProject",
                                                  version:vers,
                                                  install:install,
                                                  cpe:cpe,
                                                  concluded:version[0] ),
                                                  port:port );
        exit( 0 );
      }
    }
  }
}

exit( 0 );
