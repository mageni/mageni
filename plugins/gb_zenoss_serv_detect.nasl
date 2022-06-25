###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_zenoss_serv_detect.nasl 9889 2018-05-17 14:03:49Z cfischer $
#
# Zenoss Server Version Detection
#
# Authors:
# Rachana Shetty <srachan@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.800988");
  script_version("$Revision: 9889 $");
  script_tag(name:"last_modification", value:"$Date: 2018-05-17 16:03:49 +0200 (Thu, 17 May 2018) $");
  script_tag(name:"creation_date", value:"2010-03-05 10:09:57 +0100 (Fri, 05 Mar 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Zenoss Server Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80, 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"This script detects the installed version of Zenoss Server
  and sets the result in KB.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

port = get_http_port( default:8080 );

req = http_get( item:"/zport/acl_users/cookieAuthHelper/login_form", port:port );
res = http_keepalive_send_recv( port:port, data:req );
if( "Zenoss Login" >!< res ) exit( 0 );

install = "/";
version = "unknown";

vers = eregmatch( pattern:"<span>([0-9.]+)" ,string:res );
if( ! isnull( vers[1] ) ) version = vers[1];

set_kb_item( name:"www/" + port + "/Zenoss", value:version );
set_kb_item( name:"ZenossServer/detected", value:TRUE );
register_and_report_cpe( app:"Zenoss Server", ver:version, concluded:vers[0], base:"cpe:/a:zenoss:zenoss:", expr:"^([0-9.]+)", insloc:install, regPort:port );

exit( 0 );