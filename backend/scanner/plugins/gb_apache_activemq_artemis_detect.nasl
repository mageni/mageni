###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_activemq_artemis_detect.nasl 11015 2018-08-17 06:31:19Z cfischer $
#
# Apache ActiveMQ Artemis Detection
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
#
# Copyright:
# Copyright (c) 2015 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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
  script_oid("1.3.6.1.4.1.25623.1.0.809341");
  script_version("$Revision: 11015 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-08-17 08:31:19 +0200 (Fri, 17 Aug 2018) $");
  script_tag(name:"creation_date", value:"2016-10-06 14:54:29 +0530 (Thu, 06 Oct 2016)");
  script_name("Apache ActiveMQ Artemis Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 8161);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"The script sends a connection
  request to the server and attempts to detect Apache ActiveMQ Artemis.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

port = get_http_port( default:8161 );

url = "/api/index.html";
req = http_get( item:url, port:port );
buf = http_keepalive_send_recv( port:port, data:req );
if( ! buf ) exit( 0 );

if( egrep( pattern:"<title>ActiveMQ Artemis Web .* API</title>", string:buf, icase:TRUE ) ||
    'WWW-Authenticate: basic realm="ActiveMQ"' >< buf ) {

  install = "/";
  appVer = "unknown";
  conclUrl = report_vuln_url( port:port, url:url, url_only:TRUE );

  version = eregmatch( pattern:'<title>ActiveMQ Artemis Web ([0-9.]+) API</title>', string:buf );
  if( version[1] ) appVer = version[1];

  cpe = build_cpe( value:appVer, exp:"^([0-9.]+)", base:"cpe:/a:apache:activemq_artemis:" );
  if( ! cpe )
    cpe = "cpe:/a:apache:activemq_artemis";

  set_kb_item( name:"ActiveMQ/Artemis/installed", value:TRUE );

  register_product( cpe:cpe, location:install, port:port, service:"www" );

  log_message( data:build_detection_report( app:"Apache ActiveMQ Artemis",
                                            install:install,
                                            version:appVer,
                                            concluded:version[0],
                                            concludedUrl:conclUrl,
                                            cpe:cpe ),
                                            port:port );
}

exit( 0 );
