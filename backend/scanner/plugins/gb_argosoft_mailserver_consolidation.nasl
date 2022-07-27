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
  script_oid("1.3.6.1.4.1.25623.1.0.113668");
  script_version("2020-04-04T12:55:21+0000");
  script_tag(name:"last_modification", value:"2020-04-06 12:43:58 +0000 (Mon, 06 Apr 2020)");
  script_tag(name:"creation_date", value:"2020-04-03 11:30:00 +0100 (Fri, 03 Apr 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("ArgoSoft Mail Server Detection (Consolidation)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_argosoft_mailserver_http_detect.nasl", "gb_argosoft_mailserver_smtp_detect.nasl",
                      "gb_argosoft_mailserver_pop3_detect.nasl");
  script_mandatory_keys("argosoft/mailserver/detected");

  script_tag(name:"summary", value:"Checks whether Argosoft Mail Server
  is present on the target system.");

  exit(0);
}

CPE = "cpe:/a:argosoft:argosoft_mail_server";

include( "host_details.inc" );
include( "cpe.inc" );

version = "unknown";
concluded = "";
extra = "Concluded from the following protocols:";

foreach proto( make_list( "smtp", "http", "pop3" ) ) {
  if( ! ports = get_kb_list( "argosoft/mailserver/" + proto + "/port" ) )
    continue;
  protoupper = toupper( proto );
  foreach port( ports ) {
    vers = get_kb_item( "argosoft/mailserver/" + proto + "/" + port + "/version" );
    concl = get_kb_item( "argosoft/mailserver/" + proto + "/" + port + "/concluded" );
    if( ! isnull( vers ) && version == "unknown" )
      version = vers;
    if( concluded == "" )
      concluded = protoupper;
    else if( protoupper >!< concluded )
      concluded += ", " + protoupper;
    if( ! isnull( concl ) ) {
      extra += '\n\n' + port + "/" + protoupper + ":";
      extra += '\n    ' + concl;
    }

    if( proto == "http" )
      service = "www";
    else
      service = proto;

    cpe = build_cpe( value: vers, exp: "([0-9.]+)", base: CPE + ":" );
    register_product( cpe: cpe, location: port + "/tcp", port: port, service: service );
  }
}

if( version != "unknown" )
  CPE = build_cpe( value: version, exp: "([0-9.]+)", base: CPE + ":" );

report = build_detection_report( app: "ArgoSoft Mail Server",
                                 version: version,
                                 cpe: CPE,
                                 concluded: concluded,
                                 extra: extra );

log_message( port: 0, data: report );

exit( 0 );
