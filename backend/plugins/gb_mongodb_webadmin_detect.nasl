###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mongodb_webadmin_detect.nasl 9633 2018-04-26 14:07:08Z jschulte $
#
# MongoDB Web Admin Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.100748");
  script_version("$Revision: 9633 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-26 16:07:08 +0200 (Thu, 26 Apr 2018) $");
  script_tag(name:"creation_date", value:"2010-08-06 15:09:20 +0200 (Fri, 06 Aug 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("MongoDB Web Admin Detection");
  script_family("Product detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 28017);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"The script sends a connection request to the server and attempts to
  extract the version number from the reply.");

  script_xref(name:"URL", value:"http://www.mongodb.org/");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("cpe.inc");

port = get_http_port( default:28017 );
banner = get_http_banner( port:port );
if( ! banner || "Server:" >< banner ) exit( 0 );

buf = http_get_cache( item:"/", port:port );

if( ( buf =~ '<title>[^<]*mongod[^<]*</title>' && 'buildInfo' >< buf ) || ( "unauthorized db:admin lock type" >< buf ) ) {

  set_kb_item( name:"mongodb/webadmin/port", value:port );
  vers    = "unknown";
  install = "/";

  if( "db version" >< buf ) {

    version = eregmatch( pattern:'db version v([^\n, ]+)', string:buf );

    if( ! isnull( version[1] ) ) {
      vers = version[1];
      set_kb_item( name:"mongodb/webadmin/version", value:vers );
    }
  }

  cpe = build_cpe( value:vers, exp:"^([0-9.]+)", base:"cpe:/a:mongodb:mongodb:" );
  if( isnull( cpe ) )
    cpe = "cpe:/a:mongodb:mongodb";

  register_product( cpe:cpe, location:install, port:port );

  log_message( port:port, data:build_detection_report( app:"MongoDB Web Admin", version:vers, install:install, cpe:cpe, concluded:version[0] ) );
}

exit( 0 );
