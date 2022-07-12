# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.113700");
  script_version("2020-06-08T12:04:49+0000");
  script_tag(name:"last_modification", value:"2020-06-08 12:04:49 +0000 (Mon, 08 Jun 2020)");
  script_tag(name:"creation_date", value:"2020-06-08 13:57:00 +0200 (Mon, 08 Jun 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_name("libupnp Detection (Consolidation)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_libupnp_http_detect.nasl", "gb_libupnp_upnp_detect.nasl");
  script_mandatory_keys("libupnp/detected");

  script_tag(name:"summary", value:"Reports a detect libupnp installation.");

  script_xref(name:"URL", value:"https://pupnp.sourceforge.io/");

  exit(0);
}

CPE_base = "cpe:/a:libupnp_project:libupnp";

include( "host_details.inc" );
include( "cpe.inc" );

something_to_report = FALSE;
version = "unknown";
concluded = "";

foreach proto( make_list( "upnp", "http" ) ) {
  if( ports = get_kb_list( "libupnp/" + proto + "/port" ) ) {
    something_to_report = TRUE;
    foreach port( ports ) {
      proto_version = get_kb_item( "libupnp/" + proto + "/" + port + "/version" );
      if( version == "unknown" && proto_version != "unknown" && proto_version != "" )
        version = proto_version;
      concl = get_kb_item( "libupnp/" + proto + "/" + port + "/concluded" );
      if( ! cpe = build_cpe( value: proto_version, exp: "([0-9.]+)", base: CPE_base + ":" ) )
        cpe = CPE_base;
      if( proto == "http" )
        tproto = "tcp";
      if( proto == "upnp" )
        tproto = "udp";
      register_product( cpe: cpe, location: tproto + "/" + port, port: port, proto: tproto, service: proto );
      concluded += '\n\n' + toupper(tproto) + "/" + port + ':\n' + concl;
    }
  }
}

if( something_to_report ) {
  if( ! CPE = build_cpe( value: version, exp: "([0-9.]+)", base: CPE_base + ":" ) )
    CPE = CPE_base;
  report = build_detection_report( app: "libupnp",
                                   version: version,
                                   install: "/",
                                   cpe: CPE,
                                   concluded: concluded );
  log_message( data: report, port: 0 );
}

exit( 0 );
