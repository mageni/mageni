###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_autodesk_backburner_detect.nasl 10888 2018-08-10 12:08:02Z cfischer $
#
# Autodesk Backburner Detection
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.808171");
  script_version("$Revision: 10888 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 14:08:02 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2016-08-23 15:56:59 +0530 (Tue, 23 Aug 2016)");
  script_name("Autodesk Backburner Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detects the installed version of
  Autodesk Backburner.

  This script sends a HTTP GET request and try to fetch the version of
  Autodesk Backburner from the response.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );

foreach dir( make_list_unique( "/", "/Backburner", cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" ) dir = "";

  res = http_get_cache( item:dir + "/", port:port );

  if( res =~ "^HTTP/1\.[01] 200" && res =~ '<title>Autodesk Backburner Monitor .*</title>' ) {

    vers = "unknown";

    # <title>Autodesk Backburner Monitor 2010.2  (Build 368)</title>
    # <title>Autodesk Backburner Monitor 2017.1.0  (Build 2233)</title>
    version = eregmatch( pattern:'<title>Autodesk Backburner Monitor ([0-9.]+).*Build ([0-9]+)', string:res );
    if( version[1] && version[2] )
      vers = version[1] + "." + version[2];

    set_kb_item( name:"Autodesk/Backburner/detected", value:TRUE );

    cpe = build_cpe( value:vers, exp:"^([0-9.]+)", base:"cpe:/a:autodesk:autodesk_backburner:" );
    if( isnull( cpe ) )
      cpe = "cpe:/a:autodesk:autodesk_backburner";

    register_product( cpe:cpe, location:install, port:port );

    log_message( data:build_detection_report( app:"Autodesk Backburner",
                                              version:vers,
                                              install:install,
                                              cpe:cpe,
                                              concluded:version[0] ),
                                              port:port );
    exit( 0 );
  }
}

exit( 0 );
