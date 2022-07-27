###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_monsta_ftp_detect.nasl 10911 2018-08-10 15:16:34Z cfischer $
#
# Monsta FTP Version Detection
#
# Authors:
# Rinu Kuriaksoe <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.806051");
  script_version("$Revision: 10911 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 17:16:34 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2015-09-14 17:59:32 +0530 (Mon, 14 Sep 2015)");
  script_name("Monsta FTP Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detects the installed version of
  Monsta FTP.

  This script sends HTTP GET request and try to get the version from the
  response, and sets the result in KB.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

port = get_http_port( default:80 );

foreach dir( make_list_unique( "/", "/Monsta-FTP-master", "/ftp", cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" ) dir = "";

  rcvRes = http_get_cache( item: dir + "/", port:port );

  if( 'loginFormTitle">Monsta FTP' >< rcvRes && '>monsta' >< rcvRes ) {

    version = "unknown";

    ver = eregmatch( pattern:"Monsta FTP v([0-9.]+)", string:rcvRes );
    if( ver[1] ) version = ver[1];

    tmp_version = version + " under " + install;
    set_kb_item( name:"www/" + port + "/Monsta-FTP-master", value:tmp_version );
    set_kb_item( name:"Monsta-FTP-master/Installed", value:TRUE );

    ## cpe is not available , taking cpe as cpe:/a:monsta:ftp
    cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:monsta:ftp:" );
    if( ! cpe )
      cpe = "cpe:/a:monsta:ftp";

    register_product( cpe:cpe, location:install, port:port );

    log_message( data:build_detection_report( app:"Monsta-FTP-master",
                                              version:version,
                                              install:install,
                                              cpe:cpe,
                                              concluded:ver[0] ),
                                              port:port );
  }
}

exit( 0 );