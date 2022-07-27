# Copyright (C) 2017 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.107131");
  script_version("2021-09-28T08:54:56+0000");
  script_tag(name:"last_modification", value:"2021-09-28 10:14:46 +0000 (Tue, 28 Sep 2021)");
  script_tag(name:"creation_date", value:"2017-01-19 16:11:25 +0530 (Thu, 19 Jan 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("ManageEngine ADManager Plus Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of ManageEngine ADManager Plus.");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port( default:8080 );

res = http_get_cache( item:"/", port:port );

if( res =~ "^HTTP/1\.[01] 200" && ( "<title>ManageEngine" >< res && "ADManager Plus</title>" >< res ) &&
    '<input type="hidden" name="AUTHRULE_NAME" value="ADAuthenticator">' >< res &&
    "admp.login.browserinfo.message" >< res ) {

  set_kb_item( name:"manageengine/admanager_plus/detected", value:TRUE );
  set_kb_item( name:"manageengine/admanager_plus/http/detected", value:TRUE );
  set_kb_item( name:"manageengine/admanager_plus/http/port", value:port );

  version = "unknown";

  # src="js/framework/jsencrypt.min.js?v=7102"
  vers = eregmatch( pattern:"[a-zA-Z0-9.-]+.(js|css)\?v=([0-9]+)", string:res );

  if( ! isnull( vers[2] ) ) {
    build = vers[2];
    if( strlen( build ) == 4 )
      version = build[0] + "." + build[1];
    else
      if( strlen( build ) > 4 )
        version = substr( build, 0, 1 ) + "." + build[2];

    set_kb_item( name:"manageengine/admanager_plus/http/" + port + "/concluded", value:vers[0] );
  }

  set_kb_item( name:"manageengine/admanager_plus/http/" + port + "/version", value:version );
  set_kb_item( name:"manageengine/admanager_plus/http/" + port + "/build", value:build );
}

exit( 0 );
