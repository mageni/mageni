###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_bigtree_detect.nasl 11408 2018-09-15 11:35:21Z cfischer $
#
# BigTree CMS Remote Version Detection
#
# Authors:
# Tushar Khelge <ktushar@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.807791");
  script_version("$Revision: 11408 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-15 13:35:21 +0200 (Sat, 15 Sep 2018) $");
  script_tag(name:"creation_date", value:"2016-04-18 12:45:32 +0530 (Mon, 18 Apr 2016)");
  script_name("BigTree CMS Remote Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detection of installed version
  of BigTree CMS.

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
if( ! can_host_php( port:port ) ) exit( 0 );

foreach dir( make_list_unique( "/", "/BigTree", "/cms", "/bigtree", cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" ) dir = "";

  foreach url( make_list( dir + "/site/index.php/admin/login/", dir + "/admin/login/" ) ) {

    req = http_get( item:url, port:port );
    res = http_keepalive_send_recv( port:port, data:req );
    if( isnull( res ) ) continue;

    if( ( "<title>BigTree Site Login</title>" >< res && "<label>Password</label>" >< res ) ||
        '<a href="http://www.bigtreecms.com" class="login_logo"' >< res ) {

      vers = "unknown";

      # Version was removed in 4.2+ from the login page: https://github.com/bigtreecms/BigTree-CMS/issues/269
      # TODO: Try to find the version from some other place
      version = eregmatch( pattern:'Version ([0-9.]+)', string:res );
      if( version[1]) vers = version[1];

      set_kb_item( name:"BigTree/Installed", value:TRUE );

      cpe = build_cpe( value:vers, exp:"^([0-9.]+)", base:"cpe:/a:bigtree:bigtree:" );
      if( ! cpe )
        cpe = "cpe:/a:bigtree:bigtree";

      register_product( cpe:cpe, location:install, port:port );

      log_message( data:build_detection_report( app:"BigTree CMS",
                                                version:vers,
                                                install:install,
                                                cpe:cpe,
                                                concluded:version[0] ),
                                                port:port );
    }
  }
}

exit( 0 );
