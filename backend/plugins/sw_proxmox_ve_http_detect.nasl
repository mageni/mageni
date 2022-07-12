# Copyright (C) 2016 SCHUTZWERK GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.111090");
  script_version("2021-03-25T07:04:23+0000");
  script_tag(name:"last_modification", value:"2021-03-25 07:04:23 +0000 (Thu, 25 Mar 2021)");
  script_tag(name:"creation_date", value:"2016-03-17 10:42:39 +0100 (Thu, 17 Mar 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Proxmox Virtual Environment (VE, PVE) Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2016 SCHUTZWERK GmbH");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 3128, 8006);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Proxmox Virtual Environment (VE, PVE).");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port( default:8006 );
banner = http_get_remote_headers( port:port );
res = http_get_cache( item:"/", port:port );

detection_patterns = make_list(
  # Server: pve-api-daemon/3.0
  "^Server\s*:\s*pve-api-daemon",
  # <title>$hostname - Proxmox Virtual Environment</title>
  "<title>[^>]*Proxmox Virtual Environment</title>",
  '"/pve2/(css/ext([0-9])?-pve\\.css|js/pvemanagerlib\\.js)',
  "PVE\.UserName",
  "PVE\.CSRFPreventionToken",
  # "boxheadline">Proxmox Virtual Environment 1.9</a>
  '"boxheadline">Proxmox Virtual Environment ',
  # Setup: { auth_cookie_name: 'PVEAuthCookie' },
  "'PVEAuthCookie'" );

found = 0;
concluded = ""; # nb: To make openvas-nasl-lint happy...

foreach pattern( detection_patterns ) {

  if( "pve-api-daemon" >< pattern )
    concl = egrep( string:banner, pattern:pattern, icase:TRUE );
  else
    concl = egrep( string:res, pattern:pattern, icase:FALSE );

  if( concl ) {
    if( concluded )
      concluded += '\n';

    # nb: Minor formatting change for the reporting.
    concl = chomp( concl );
    concl = ereg_replace( string:concl, pattern:"^(\s+)", replace:"" );
    concluded += "    " + concl;

    # Existence of the banner is always counting as a successful detection.
    if( "pve-api-daemon" >< pattern )
      found += 2;
    else
      found++;
  }
}

if( found > 1 ) {

  version = "unknown";

  set_kb_item( name:"proxmox/ve/detected", value:TRUE );
  set_kb_item( name:"proxmox/ve/http/detected", value:TRUE );
  set_kb_item( name:"proxmox/ve/http/port", value:port );

  # e.g. "boxheadline">Proxmox Virtual Environment 1.9</a>
  # nb: only available in quite old versions of Proxmox VE
  ver = eregmatch( pattern:'"boxheadline">Proxmox Virtual Environment ([0-9.]+)</a>', string:res );
  if( ver[1] )
    version = ver[1];

  if( version == "unknown" ) {
    # e.g.:
    # <link rel="stylesheet" type="text/css" href="/pve2/css/ext6-pve.css?ver=5.1-42" />
    # or:
    # <script type="text/javascript" src="/pve2/js/pvemanagerlib.js?ver=5.1-42"></script>
    ver = eregmatch( pattern:'"/pve2/(css/ext([0-9])?-pve\\.css|js/pvemanagerlib\\.js)\\?ver=([0-9.-]+)"', string:res );
    if( ver[3] )
      version = ver[3];
  }

  if( version == "unknown" ) {
    # Only the major version but still better then nothing...
    # At this point (if the css/js above failed) a full version is only available via an authenticated API and would return something like 5.0-34
    url = "/pve-docs/pve-admin-guide.html";
    req = http_get( item:url, port:port );
    res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

    # e.g.:
    # <span id="revnumber">version 5.0,</span>
    # <span id="revnumber">version 6.3,</span>
    ver = eregmatch( pattern:">version ([0-9.]+)", string:res );
    if( ver[1] ) {
      version = ver[1];
      concl_url = http_report_vuln_url( port:port, url:url, url_only:TRUE );
      concluded += '\n    ' + chomp( ver[0] );
    }
  }

  set_kb_item( name:"proxmox/ve/http/" + port + "/version", value:version );
  set_kb_item( name:"proxmox/ve/http/" + port + "/concluded", value:concluded );
  if( concl_url )
    set_kb_item( name:"proxmox/ve/http/" + port + "/concludedUrl", value:"    " + concl_url );
}

exit( 0 );