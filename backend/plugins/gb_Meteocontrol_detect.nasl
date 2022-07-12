###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_Meteocontrol_detect.nasl 9223 2018-03-27 12:39:40Z cfischer $
#
# Meteocontrol WEB'log Detection
#
# Authors:
# Tameem Eissa  <tameem.eissa@greenbone.net>
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
  script_oid("1.3.6.1.4.1.25623.1.0.107004");
  script_version("$Revision: 9223 $");
  script_tag(name:"creation_date", value:"2016-05-20 10:42:39 +0100 (Fri, 20 May 2016)");
  script_tag(name:"last_modification", value:"$Date: 2018-03-27 14:39:40 +0200 (Tue, 27 Mar 2018) $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Meteocontrol WEB'log Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"The script sends a HTTP request to the server and
  attempts to identify a Meteocontrol WEB'log Application existence from the reply .");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

port = get_http_port( default:80 );

url = "/html/en/index.html";
buf = http_get_cache( item:url, port:port );

if( buf =~ "^HTTP/1\.[01] 200" && "WEB'log" >< buf && "System Survey of the Plant" >< buf
    && '<div class="cProductname">&nbsp;WEB&#180;log</div>' >< buf ) {

  set_kb_item( name:"meteocontrol/weblog/installed", value:TRUE );

  install = "/";
  # no version info available right now
  version = "unknown";

  cpe = 'cpe:/a:meteocontrol:weblog';

  register_product( cpe:cpe, location:install, port:port );
  log_message( data:build_detection_report( app:"Meteocontrol WEBlog",
                                            version:version,
                                            install:install,
                                            cpe:cpe,
                                            concludedUrl:report_vuln_url( port:port, url:url, url_only:TRUE ) ),
                                            port:port );

}

exit( 0 );
