###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_zeuscart_detect.nasl 9043 2018-03-07 12:38:58Z cfischer $
#
# ZeusCart Version Detection
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.801250");
  script_version("$Revision: 9043 $");
  script_tag(name:"last_modification", value:"$Date: 2018-03-07 13:38:58 +0100 (Wed, 07 Mar 2018) $");
  script_tag(name:"creation_date", value:"2010-08-10 14:39:31 +0200 (Tue, 10 Aug 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("ZeusCart Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://zeuscart.com/");

  script_tag(name:"summary", value:"The script detects the version of ZeusCart on
  remote host and sets the KB.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

port = get_http_port( default:80 );
if( ! can_host_php( port:port ) ) exit( 0 );

foreach dir( make_list_unique( "/Zeuscart", "/zeuscart", cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" ) dir = "";

  res = http_get_cache( item:dir + "/index.php", port:port );

  if( egrep( pattern:'target="_blank">ZeusCart</a>', string:res, icase:TRUE ) ) {

    version = "unknown";
    vers = eregmatch( pattern:'<title> ZeusCart V(.[0-9.]+)', string:res );
    if( ! isnull( vers[1] ) ) version = chomp( vers[1] );

    set_kb_item( name:"www/" + port + "/ZeusCart", value:version );
    set_kb_item( name:"zeuscart/installed", value:TRUE );

    cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:zeuscart:zeuscart:" );
    if( isnull( cpe ) )
      cpe = "cpe:/a:zeuscart:zeuscart";

    register_product( cpe:cpe, location:install, port:port );

    log_message( data:build_detection_report( app:"ZeusCart",
                                              version:version,
                                              install:install,
                                              cpe:cpe,
                                              concluded:vers[0] ),
                                              port:port );
  }
}

exit( 0 );
