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
  script_oid("1.3.6.1.4.1.25623.1.0.112137");
  script_version("2022-08-10T12:54:52+0000");
  script_tag(name:"last_modification", value:"2022-08-10 12:54:52 +0000 (Wed, 10 Aug 2022)");
  script_tag(name:"creation_date", value:"2017-11-23 10:50:05 +0100 (Thu, 23 Nov 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Greenbone Security Manager (GSM) / Greenbone OS (GOS) Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80, 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of the Greenbone Security Manager (GSM) /
  Greenbone OS (GOS).");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port( default:443 );

# nb: On GOS 5.0+ the URL is just "/login" but GSA has a "catchall" login page so this URL works as well
url = "/login/login.html";
buf = http_get_cache( item:url, port:port );

if( buf =~ "^HTTP/1\.[01] 200" &&
    (
      # nb: GOS 4.3 and below
      ( "<title>Greenbone Security Assistant" >< buf && "Greenbone OS" >< buf ) ||
      # nb: GOS 5.0+
      '"title">Greenbone Security Manager</span>' >< buf || "<title>Greenbone Security Manager</title>" >< buf ||
      # nb: GOS 22.04+
      "<title>Greenbone Enterprise Appliance</title>" >< buf
    )
  ) {

  set_kb_item( name:"greenbone/gos/detected", value:TRUE );
  set_kb_item( name:"greenbone/gos/http/detected", value:TRUE );
  set_kb_item( name:"greenbone/gos/http/port", value:port );
  set_kb_item( name:"greenbone/gos/http/" + port + "/detected", value:TRUE );

  # nb: To tell http_can_host_asp and http_can_host_php from http_func.inc that the service doesn't support these
  replace_kb_item( name:"www/" + port + "/can_host_php", value:"no" );
  replace_kb_item( name:"www/" + port + "/can_host_asp", value:"no" );

  vers = "unknown";

  # <div class="gos_version">Greenbone OS 1.2.3</div>
  # <span class="version">Greenbone OS 1.2.3</span>
  # <span class="version">Version Greenbone OS 1.2.3</span>
  version = eregmatch( string:buf, pattern:'<(div|span) class="(gos_)?version">(Version )?Greenbone OS ([^<]+)</(div|span)>', icase:FALSE );
  if( ! isnull( version[4] ) ) {
    vers = version[4];
    concluded = version[0];
    conclurl  = http_report_vuln_url( port:port, url:url, url_only:TRUE );
  }

  # This is GOS 5.0+
  if( vers == "unknown" ) {
    url2 = "/config.js";
    req = http_get( item:url2, port:port );
    buf2 = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

    # config = {
    #     vendorVersion: 'Greenbone OS 5.0.1',
    #     vendorLabel: 'gsm-one_label.svg',
    # }
    #
    # or:
    #
    # config = {
    #     vendorVersion: 'Greenbone OS 5.0.1',
    #     vendorLabel: 'gsm-600_label.svg',
    # }
    if( buf2 =~ "^HTTP/1\.[01] 200" && "Greenbone OS" >< buf2 ) {
      version = eregmatch( string:buf2, pattern:"vendorVersion: 'Greenbone OS ([^']+)',", icase:FALSE );
      if( ! isnull( version[1] ) ) {
        vers = version[1];
        concluded = version[0];
        conclurl  = http_report_vuln_url( port:port, url:"/login", url_only:TRUE ); # nb: See note about /login/login.html above...
      }
    }
  }

  type = "unknown";
  # e.g.:
  # <img src="/img/gsm-one_label.svg"></img>
  # <img src="/img/GSM_DEMO_logo_95x130.png" alt=""></td>
  # vendorLabel: 'gsm-one_label.svg',
  _type = eregmatch( string:buf, pattern:'<img src="/img/gsm-([^>]+)_label\\.svg"></img>', icase:FALSE );
  if( ! _type[1] ) {
    _type = eregmatch( string:buf, pattern:'<img src="/img/GSM_([^>]+)_logo_95x130\\.png" alt=""></td>', icase:FALSE );
  }

  if( ! _type[1] ) {
    _type = eregmatch( string:buf2, pattern:"vendorLabel: 'gsm-([^']+)_label\.svg',", icase:FALSE );
    if( _type[1] )
      conclurl += " and " + http_report_vuln_url( port:port, url:url2, url_only:TRUE );
  }

  if( _type[1] ) {
    # nb: Products are named uppercase
    type = toupper( _type[1] );
    concluded += '\n' + _type[0];
  }

  set_kb_item( name:"greenbone/gos/http/" + port + "/version", value:vers );
  set_kb_item( name:"greenbone/gsm/http/" + port + "/type", value:type );

  if( concluded ) {
    set_kb_item( name:"greenbone/gos/http/" + port + "/concluded", value:concluded );
    set_kb_item( name:"greenbone/gos/http/" + port + "/concludedUrl", value:conclurl );
  }
}

exit( 0 );
