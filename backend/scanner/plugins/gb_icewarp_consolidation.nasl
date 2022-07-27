# Copyright (C) 2017 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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
  script_oid("1.3.6.1.4.1.25623.1.0.140330");
  script_version("2020-11-05T10:18:37+0000");
  script_tag(name:"last_modification", value:"2020-11-06 11:47:26 +0000 (Fri, 06 Nov 2020)");
  script_tag(name:"creation_date", value:"2017-08-28 15:51:57 +0700 (Mon, 28 Aug 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("IceWarp Mail Server Detection (Consolidation)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_icewarp_http_detect.nasl", "gb_icewarp_pop3_detect.nasl",
                      "gb_icewarp_smtp_detect.nasl", "gb_icewarp_imap_detect.nasl");
  script_mandatory_keys("icewarp/mailserver/detected");

  script_xref(name:"URL", value:"http://www.icewarp.com/");

  script_tag(name:"summary", value:"Consolidation of detections of IceWarp Mail Server.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include( "cpe.inc" );
include( "host_details.inc" );

CPE = "cpe:/a:icewarp:mail_server";
version = "unknown";
concluded = "Concluded from:";

foreach proto( make_list( "http", "pop3", "smtp", "imap" ) ) {
  foreach port( get_kb_list( "icewarp/mailserver/" + proto + "/port" ) ) {
    if( ! vers = get_kb_item( "icewarp/mailserver/" + proto + "/" + port + "/version" ) )
      continue;

    if( version == "unknown" && vers != "unknown" )
      version = vers;

    concl = get_kb_item( "icewarp/mailserver/" + proto + "/" + port + "/concluded" );

    concluded += '\n\n' + toupper(proto) + "/" + port;
    if( ! isnull( concl ) )
      concluded += '\n"' + concl + '"';

    service = proto;
    if( service == "http" )
      service = "www";

    if( ! cpe = build_cpe( value: vers, exp: "([0-9.]+)", base: CPE + ":" ) )
      cpe = CPE;

    register_product( cpe: cpe, location: port + "/tcp", port: port, proto: "tcp", service: service );
  }
}

if( ! cpe = build_cpe( value: version, exp: "([0-9.]+)", base: CPE + ":" ) )
  cpe = CPE;

report = build_detection_report( app: "IceWarp Mail Server",
                                 version: version,
                                 cpe: cpe,
                                 concluded: concluded );

log_message( data: report, port: 0 );

exit( 0 );
