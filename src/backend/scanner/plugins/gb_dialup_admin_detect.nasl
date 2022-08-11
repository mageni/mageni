###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dialup_admin_detect.nasl 9099 2018-03-14 12:27:19Z mmartin $
#
# dialup_admin Detection
#
# Authors:
# Michael Martin <michael.martin@greenbone.net>
# Christian Fischer <christian.fischer@greenbone.net>
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108430");
  script_version("$Revision: 9099 $");
  script_tag(name:"last_modification", value:"$Date: 2018-03-14 13:27:19 +0100 (Wed, 14 Mar 2018) $");
  script_tag(name:"creation_date", value:"2018-03-14 09:41:54 +0100 (Wed, 14 Mar 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("dialup_admin Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detection of dialup_admin interface for the freeradius radius server.

  The script sends a connection request to the server and attempts to detect dialup_admin
  web based administration interface for the freeradius radius server.");

  script_xref(name:"URL", value:"https://github.com/FreeRADIUS/dialup-admin");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

port = get_http_port( default:80 );

rootInstalled = FALSE;

foreach dir( make_list_unique( "/", "/dialup", cgi_dirs( port:port ) ) ) {

  if( rootInstalled ) break;

  install = dir;
  if( dir == "/" ) dir = "";

  url = dir + "/";
  res = http_get_cache( port:port, item:url );

  url2 = dir + "/content.html";
  res2 = http_get_cache( port:port, item:url2 );

  # <title>
  #dialup administration</title>
  if( egrep( string:res, pattern:"dialup administration</title>" ) || egrep( string:res2, pattern:"<b>A web based administration interface for the freeradius radius server</b>" ) ) {

    # Version isn't exposed by the application
    version = "unknown";

    if( install == "/" ) rootInstalled = TRUE;
    set_kb_item( name:"dialup_admin/detected", value:TRUE );
    set_kb_item( name:"dialup_admin/" + port + "/version", value:version );

    cpe = "cpe:/a:freeradius:dialup_admin";

    register_product( cpe:cpe, location:install, port:port );

    log_message( data:build_detection_report( app:"dialup_admin",
                                              version:version,
                                              install:install,
                                              cpe:cpe ),
                                              port:port );
  }
}
