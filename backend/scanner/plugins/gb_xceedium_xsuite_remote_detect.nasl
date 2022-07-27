###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_xceedium_xsuite_remote_detect.nasl 10922 2018-08-10 19:21:48Z cfischer $
#
# Xceedium Xsuite Remote Version Detection
#
# Authors:
# Rinu Kuriaksoe <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.807087");
  script_version("$Revision: 10922 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 21:21:48 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2016-03-03 18:23:52 +0530 (Thu, 03 Mar 2016)");
  script_name("Xceedium Xsuite Remote Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detection of installed version
  of Xceedium Xsuite.

  This script sends HTTP GET request and try to get the version from the
  response, and sets the result in KB.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

port = get_http_port( default:80 );

foreach dir( make_list_unique( "/", cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" ) dir = "";

  rcvRes = http_get_cache( item:dir + "/", port:port );

  if( '<title>Xceedium Xsuite' >< rcvRes && 'User:' >< rcvRes &&
      'Password:' >< rcvRes ) {

    version = "unknown";

    set_kb_item( name:"www/" + port + "/Xceedium Xsuite", value:version );
    set_kb_item( name:"Xceedium/Xsuite/Installed", value:TRUE );

    cpe = "cpe:/a:xceedium:xsuite";

    register_product( cpe:cpe, location:install, port:port );

    log_message( data:build_detection_report( app:"Xceedium Xsuite",
                                              version:version,
                                              install:install,
                                              cpe:cpe ),
                                              port:port );
  }
}

exit( 0 );
