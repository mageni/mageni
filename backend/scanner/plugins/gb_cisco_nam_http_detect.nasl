###############################################################################
# OpenVAS Vulnerability Test
#
# Cisco Network Analysis Module Web Interface Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105458");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2020-06-25T10:23:49+0000");
  script_tag(name:"last_modification", value:"2020-06-30 10:45:10 +0000 (Tue, 30 Jun 2020)");
  script_tag(name:"creation_date", value:"2015-11-18 13:39:52 +0100 (Wed, 18 Nov 2015)");

  script_name("Cisco Network Analysis Module Detection (HTTP)");

  script_tag(name:"summary", value:"This script performs HTTP based detection of the Cisco Network Analysis Module.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80, 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = http_get_port( default:443 );

url = "/authenticate/login";

buf = http_get_cache( port:port, item:url );

if( ( "<title>NAM Login</title>" >< buf && "Cisco Prime" >< buf ) ||
    ( 'productName="Network Analysis Module"' >< buf ) ) {

  version = "unknown";

  set_kb_item( name:"cisco/nam/detected", value:TRUE );
  set_kb_item( name:"cisco/nam/http/port", value:port );

  # productVersion="Version 6.4.2"
  vers = eregmatch( pattern:'productVersion="Version ([^"]+)"', string:buf );
  if( ! isnull( vers[1] ) ) {
    version = vers[1];
    set_kb_item( name:"cisco/nam/http/" + port + "/concluded", value:vers[0] );
  }

  set_kb_item( name:"cisco/nam/http/" + port + "/version", value:version );
}

exit(0);
