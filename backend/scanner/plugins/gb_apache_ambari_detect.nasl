################################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_ambari_detect.nasl 11021 2018-08-17 07:48:11Z cfischer $
#
# Apache Ambari Detection
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.808648");
  script_version("$Revision: 11021 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-08-17 09:48:11 +0200 (Fri, 17 Aug 2018) $");
  script_tag(name:"creation_date", value:"2016-08-09 18:35:29 +0530 (Tue, 09 Aug 2016)");
  script_name("Apache Ambari Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detects the installed version of
  Apache Ambari.

  This script sends HTTP GET request and try to get the version of Apache
  Ambari from the response, and sets the result in KB .");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");
include("misc_func.inc");

port = get_http_port( default:8080 );

url = "/javascripts/app.js";

req = http_get_req( port:port, url:url, add_headers:make_array( "Accept-Encoding", "gzip, deflate" ) );
rcvRes = http_keepalive_send_recv( port:port, data:req );

if( rcvRes =~ "HTTP/1\.[0-1] 200" && "Ambari" >< rcvRes && rcvRes =~ "Licensed under the Apache License" ) {

  version = "unknown";
  install = "/";
  conclUrl = report_vuln_url( port:port, url:url, url_only:TRUE );

  # Ambari has three digits version codes but the App.version contains something like 2.5.0.3 where .3 doesn't match the actual version (internal version number?)
  vers = eregmatch( pattern:"App.version = '([0-9]\.[0-9]\.[0-9])(\.[0-9.])?';", string:rcvRes );
  if( vers[1] ) version = vers[1];

  set_kb_item( name:"Apache/Ambari/Installed", value:TRUE );

  cpe = build_cpe( value:version, exp:"([0-9.]+)", base:"cpe:/a:apache:ambari:" );
  if( ! cpe )
    cpe = "cpe:/a:apache:ambari";

  register_product( cpe:cpe, location:install, port:port );

  log_message( data:build_detection_report( app:"Apache Ambari",
                                            version:version,
                                            install:install,
                                            cpe:cpe,
                                            concludedUrl:conclUrl,
                                            concluded:vers[0] ),
                                            port:port );
}

exit( 0 );
