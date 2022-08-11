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
  script_oid("1.3.6.1.4.1.25623.1.0.113672");
  script_version("2020-04-09T09:49:54+0000");
  script_tag(name:"last_modification", value:"2020-04-14 09:52:40 +0000 (Tue, 14 Apr 2020)");
  script_tag(name:"creation_date", value:"2020-04-09 11:40:00 +0100 (Thu, 09 Apr 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Sofia-SIP Library Detection (SIP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("sip_detection.nasl");
  script_mandatory_keys("sip/banner/available");

  script_tag(name:"summary", value:"Checks whether the Sofia-SIP Library is present on
  the target system and if so, tries to figure out the installed version.");

  script_xref(name:"URL", value:"http://sofia-sip.sourceforge.net/");

  exit(0);
}

CPE = "cpe:/a:sofia-sip:sofia-sip:";

include( "host_details.inc" );
include( "misc_func.inc" );
include( "sip.inc" );
include( "cpe.inc" );

infos = sip_get_port_proto( default_port: "5060", default_proto: "udp" );
port = infos["port"];
proto = infos["proto"];

banner = sip_get_banner( port: port, proto: proto );

if( banner =~ "sofia-sip" ) {
  set_kb_item( name: "sofia-sip/detected", value: TRUE );

  version = "unknown";

  ver = eregmatch( string: banner, pattern: "sofia-sip/([0-9.]+)" );
  if( ! isnull( ver[1] ) ) {
    version = ver[1];
  }

  register_and_report_cpe( app: "Sofia-SIP Library",
                           ver: version,
                           concluded: ver[0],
                           base: CPE,
                           expr: "([0-9.]+)",
                           insloc: port + "/" + proto,
                           regPort: port,
                           regProto: proto,
                           regService: "sip" );
}

exit( 0 );
