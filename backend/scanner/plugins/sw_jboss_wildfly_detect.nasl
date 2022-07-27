###############################################################################
# OpenVAS Vulnerability Test
# $Id: sw_jboss_wildfly_detect.nasl 10922 2018-08-10 19:21:48Z cfischer $
#
# JBoss WildFly Application Server Detection
#
# Authors:
# Christian Fischer <info@schutzwerk.com>
#
# Copyright:
# Copyright (c) 2015 SCHUTZWERK GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.111036");
  script_version("$Revision: 10922 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 21:21:48 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2015-09-07 12:00:00 +0200 (Mon, 07 Sep 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_name("JBoss WildFly Application Server Detection");

  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2015 SCHUTZWERK GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"The script sends a HTTP
  request to the server and attempts to identify a JBoss WildFly Application Server
  and its version from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("cpe.inc");

port = get_http_port( default:8080 );
banner = get_http_banner( port:port );

if( concluded = eregmatch( string: banner, pattern: "Server: WildFly[ /]?([0-9.]?)", icase:TRUE ) ) {
  installed = 1;
} else {

  buf = http_get_cache( item:"/", port:port );
  if( concluded = eregmatch( string: buf, pattern: "Welcome to WildFly ([0-9.]?)" ) ) {
    installed = 1;
  } else
  {
    req = http_get( item:"/documentation.html", port:port );
    buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

    if( concluded = eregmatch( string: buf, pattern: "WildFly ([0-9.]?) Documentation" ) ) {
      installed = 1;
    }
  }
}

if( installed )
{
  set_kb_item(name:"JBoss/WildFly/installed", value:TRUE);

  cpe = build_cpe( value: concluded[1], exp:"^([0-9.]+)",base:"cpe:/a:redhat:jboss_wildfly_application_server:" );
  if( isnull( cpe ) )
    cpe = 'cpe:/a:redhat:jboss_wildfly_application_server';

  register_product( cpe:cpe, location:port + '/tcp', port:port );

  log_message( data: build_detection_report( app:"JBoss WildFly Application Server",
                                                 version:concluded[1],
                                                 install:port + '/tcp',
                                                 cpe:cpe,
                                                 concluded: concluded[0]),
                                                 port:port);
}

exit(0);
