###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_feng_office_detect.nasl 7166 2017-09-18 09:14:09Z cfischer $
#
# Feng Office Detection
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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
  script_oid("1.3.6.1.4.1.25623.1.0.108026");
  script_version("$Revision: 7166 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-09-18 11:14:09 +0200 (Mon, 18 Sep 2017) $");
  script_tag(name:"creation_date", value:"2016-12-20 12:00:00 +0100 (Tue, 20 Dec 2016)");
  script_name("Feng Office Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (c) 2016 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.fengoffice.com");

  script_tag(name:"summary", value:"Detection of Feng Office.

  The script sends a connection request to the host and attempts to
  identify Feng Office and its version from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

port = get_http_port( default:80 );
if( ! can_host_php( port:port ) ) exit( 0 );

rootInstalled = FALSE;

foreach dir( make_list_unique( "/", "/feng_community", "/fengoffice", "/feng", "/office", cgi_dirs( port:port ) ) ) {

  if( rootInstalled ) break;
  install = dir;
  if( dir == "/" ) dir = "";

  url = dir + "/index.php?c=access&a=login";
  req = http_get( item:url, port:port );
  res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

  if( res =~ "HTTP/1.. 200" && egrep( pattern:"Powered by .*Feng Office.* - version ", string:res ) &&
     "<title>Login</title>" >< res ) {

    version = "unknown";
    if( dir == "" ) rootInstalled = TRUE;

    ver = eregmatch( string:res, pattern:"Powered by .*Feng Office.* - version ([0-9.]+)" );
    if( ! isnull( ver[1] ) ) version = ver[1];

    tmp_version = version + " under " + install;
    set_kb_item( name:"www/" + port + "/FengOffice", value:tmp_version );
    set_kb_item( name:"FengOffice/installed", value:TRUE );

    # CPE not registered yet
    cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:fengoffice:feng_office:" );
    if( isnull( cpe ) )
      cpe = 'cpe:/a:fengoffice:feng_office';

    register_product( cpe:cpe, location:install, port:port );

    log_message( data:build_detection_report( app:"Feng Office",
                                              version:version,
                                              install:install,
                                              cpe:cpe,
                                              concluded:ver[0] ),
                                              port:port );
  }
}

exit( 0 );
