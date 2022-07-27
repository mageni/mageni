# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.113665");
  script_version("2020-04-04T12:55:21+0000");
  script_tag(name:"last_modification", value:"2020-04-06 12:43:58 +0000 (Mon, 06 Apr 2020)");
  script_tag(name:"creation_date", value:"2020-04-03 10:56:57 +0100 (Fri, 03 Apr 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("ArgoSoft Mail Server Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("argosoft_mailserver/banner");

  script_tag(name:"summary", value:"Checks whether ArgoSoft Mail Server is present on
  the target system and if so, tries to figure out the installed version.");

  exit(0);
}

include( "host_details.inc" );
include( "http_func.inc" );

port = get_http_port( default: 80 );

buf = get_http_banner( port: port );

if( buf =~ "Server\s*:\s*ArGoSoft Mail Server" ) {
  set_kb_item( name: "argosoft/mailserver/detected", value: TRUE );
  set_kb_item( name: "argosoft/mailserver/http/detected", value: TRUE );
  set_kb_item( name: "argosoft/mailserver/http/port", value: port );

  version = "unknown";

  ver = eregmatch( string: buf, pattern: 'ArGoSoft Mail Server[^\n]*(\\(([0-9.]+)\\)|v\\.([0-9.]+))', icase: TRUE );
  if( ! isnull( ver[2] ) ) {
    version = ver[2];
  } else if( ! isnull( ver[3] ) ) {
    version = ver[3];
  }

  if( version != "unknown" ) {
    set_kb_item( name: "argosoft/mailserver/http/" + port + "/version", value: version );
    set_kb_item( name: "argosoft/mailserver/http/" + port + "/concluded", value: ver[0] );
  }
}

exit( 0 );
