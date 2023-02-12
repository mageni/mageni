# Copyright (C) 2018 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140780");
  script_version("2023-01-25T10:11:07+0000");
  script_tag(name:"last_modification", value:"2023-01-25 10:11:07 +0000 (Wed, 25 Jan 2023)");
  script_tag(name:"creation_date", value:"2018-02-16 10:29:54 +0700 (Fri, 16 Feb 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_name("ManageEngine ServiceDesk Plus Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of ManageEngine ServiceDesk Plus");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port( default:8080 );

res = http_get_cache( port:port, item:"/" );

if( "<title>ManageEngine ServiceDesk Plus</title>" >< res &&
    ("j_security_check" >< res || "showSamlLocalChoice" >< res)) {

  location  = "/";
  concluded = '    URL:     ' + http_report_vuln_url( port:port, url:location, url_only:TRUE );

  # title='ManageEngine ServiceDesk Plus'>ManageEngine ServiceDesk Plus</a><span>&nbsp;&nbsp;|&nbsp;&nbsp;8.0.0</span></b></td></tr>
  version = eregmatch( string:res, pattern:"ManageEngine ServiceDesk Plus</a><span>&nbsp;&nbsp;\|&nbsp;&nbsp;([0-9.]+)", icase:TRUE );
  if( isnull( version[1] ) ) {
    # example: getCustomHtml('/custom/login/log-logo.png','ManageEngine ServiceDesk Plus','http://www.manageengine.com/products/service-desk/index.html','10.0',''); //NO OUTPUTENCODING
    # or: getCustomHtml('/custom/customimages/Custom_LoginLogo.gif','ManageEngine ServiceDesk Plus','http://www.manageengine.com/products/service-desk/index.html','9.3'); //NO OUTPUTENCODING
    version = eregmatch( string:res, pattern:"ManageEngine ServiceDesk Plus','https?://.*','([0-9.]+)'", icase:TRUE );
  }

  if( ! isnull( version[1] ) ) {
    concluded += '\n    Version: ' + version[0];
    set_kb_item( name:"manageengine/servicedesk_plus/http/" + port + "/version", value:version[1] );
  }

  # e.g.:
  # loginstyle.css?9328
  # Login.js?9328
  # /scripts/Login.js?8022
  # /style/select2.css?9425
  # /style/loginstyle.css?14103
  buildnumber = eregmatch( pattern:"\.(css|js)\?([0-9]{4,5})", string:res );
  if( ! isnull( buildnumber[2] ) ) {
    concluded += '\n    Build:   ' + buildnumber[0];
    set_kb_item( name:"manageengine/servicedesk_plus/http/" + port + "/build", value:buildnumber[2] );
  }

  set_kb_item( name:"manageengine/products/http/detected", value:TRUE );
  set_kb_item( name:"manageengine/servicedesk_plus/detected", value:TRUE );
  set_kb_item( name:"manageengine/servicedesk_plus/http/detected", value:TRUE );
  set_kb_item( name:"manageengine/servicedesk_plus/http/" + port + "/location", value:location );
  set_kb_item( name:"manageengine/servicedesk_plus/http/port", value:port );
  set_kb_item( name:"manageengine/servicedesk_plus/http/" + port + "/concluded", value:concluded );
}

exit( 0 );
