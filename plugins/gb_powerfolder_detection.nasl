###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_powerfolder_detection.nasl 10901 2018-08-10 14:09:57Z cfischer $
#
# Powerfolder Detection
#
# Authors:
# Tameem Eissa <tameem.eissa..at..greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.107009");
  script_version("$Revision: 10901 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 16:09:57 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2016-06-07 06:40:16 +0200 (Tue, 07 Jun 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("PowerFolder Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detects the installed version of PowerFolder.

  The script detects the version of PowerFolder on the remote host and sets the KB entries.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

appPort = get_http_port( default:8080 );

url = "/login";
rcvRes = http_get_cache( item:url, port:appPort );

if ( rcvRes =~ "HTTP/1\.. 200" && "powerfolder/util.js" >< rcvRes && "Please enable Javascript to use PowerFolder properly" >< rcvRes ) {
  set_kb_item( name:"powerfolder/installed", value:TRUE );
  powfolVer = "unknown";

  tmpVer = eregmatch( pattern:"Program version: ([0-9.]+)",
                      string:rcvRes );
  if ( tmpVer[1] ) {
    powfolVer = tmpVer[1];
    set_kb_item( name:"www/" + appPort + "/powerfolder", value:powfolVer );
  }

  cpe = build_cpe(value:powfolVer, exp:"^([0-9.]+)", base:"cpe:/a:powerfolder:powerfolder:");
  if ( !cpe )
    cpe = 'cpe:/a:powerfolder:powerfolder';
  register_product( cpe:cpe, location:"/", port:appPort );
  log_message( data:build_detection_report( app:"PowerFolder",
                                            version:powfolVer,
                                            install:"/",
                                            cpe:cpe,
                                            concluded:tmpVer[0],
                                            concludedUrl: report_vuln_url( port:appPort, url:url, url_only:TRUE ) ),
                                            port:appPort );
}

exit(0);
