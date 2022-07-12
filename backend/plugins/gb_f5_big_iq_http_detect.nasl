# Copyright (C) 2015 Greenbone Networks GmbH
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105165");
  script_version("2021-05-27T10:41:06+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2021-05-28 10:46:03 +0000 (Fri, 28 May 2021)");
  script_tag(name:"creation_date", value:"2015-01-12 14:37:50 +0100 (Mon, 12 Jan 2015)");

  script_name("F5 Networks BIG-IQ Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of F5 Networks BIG-IQ.");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port( default:443 );

url = "/ui/login/";
buf = http_get_cache( item:url, port:port );

# nb: Older versions of this VT had also checked for the following server banner:
# Server: webd
# but that banner might be hidden if the device is e.g. running behind a reverse proxy.
if( "<title>BIG-IQ" >!< buf || "F5 Networks" >!< buf )
  exit( 0 );

_version = "unknown";
_build = "unknown";

set_kb_item( name:"f5/big_iq/detected", value:TRUE );
set_kb_item( name:"f5/big_iq/http/detected", value:TRUE );
set_kb_item( name:"f5/big_iq/http/port", value:port );

vers = eregmatch( pattern:"\?ver=([0-9.]+)", string:buf );

if( ! isnull( vers[1] ) ) {
  version = vers[1];
  _vers = split( version, sep:".", keep:FALSE );

  _version = _vers[0] + "." + _vers[1] + "." + _vers[2];
  _build = version - ( _version + "." );

  set_kb_item( name:"f5/big_iq/http/" + port + "/concluded", value:vers[0] );
  set_kb_item( name:"f5/big_iq/http/" + port + "/concUrl", value:http_report_vuln_url( port:port, url:url, url_only:TRUE ) );
} else {
  url = "/ui/js/templates.js";
  # nb: Don't use http_get_cache() as this .js file is quite big and it also doesn't make much
  # sense to save it into the KB as it is unlikely queried again.
  req = http_get( port:port, item:url );
  buf = http_keepalive_send_recv( port:port, data:req );

  # href="https://support.f5.com/csp/knowledge-center/software/BIG-IQ?module=BIG-IQ%20Centralized%20Management&version=7.0.0"
  vers = eregmatch( pattern:"Management&version=([0-9.]+)", string:buf );
  if( ! isnull( vers[1] ) ) {
    _version = vers[1];
    set_kb_item( name:"f5/big_iq/http/" + port + "/concluded", value:vers[0] );
    set_kb_item( name:"f5/big_iq/http/" + port + "/concUrl", value:http_report_vuln_url( port:port, url:url, url_only:TRUE ) );
  }
}

set_kb_item( name:"f5/big_iq/http/" + port + "/version", value:_version );
set_kb_item( name:"f5/big_iq/http/" + port + "/build", value:_build );

exit( 0 );