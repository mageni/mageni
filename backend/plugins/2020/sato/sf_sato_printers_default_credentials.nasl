# Copyright (C) 2020 Simmons Foods, Inc.
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

CPE_PREFIX = "cpe:/o:sato:";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112770");
  script_version("2020-07-07T13:20:34+0000");
  script_tag(name:"last_modification", value:"2020-07-08 14:19:02 +0000 (Wed, 08 Jul 2020)");
  script_tag(name:"creation_date", value:"2020-04-20 16:28:43 +0000 (Mon, 20 Apr 2020)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"Mitigation");

  script_name("SATO Printers Default Credentials (HTTP)");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2020 Simmons Foods, Inc.");
  script_family("Default Accounts");
  script_dependencies("gb_sato_printer_consolidation.nasl", "gb_default_credentials_options.nasl");
  script_mandatory_keys("sato_printer/detected");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_tag(name:"summary", value:"Multiple SATO printers are shipped with default credentials for the 'settings' and 'service' user.");

  script_tag(name:"insight", value:"The printers are configured with default credentials.
  The passwords for 'settings' and 'service' default to either '0310' or '6677'.");

  script_tag(name:"impact", value:"Exploiting this vulnerability would allow an attacker to obtain potentially
  sensitive information from vulnerable devices or allow an attacker to change the configuration of the printer.
  This may aid in further attacks.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP POST request with the documented default credentials
  and checks the response.");

  script_tag(name:"solution", value:"Set the password(s) to a non-default value.");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");
include("http_func.inc");

if( ! infos = get_app_port_from_cpe_prefix( cpe:CPE_PREFIX, service:"www" ) )
  exit( 0 );

port = infos["port"];
cpe  = infos["cpe"];

if( ! get_app_location( cpe:cpe, port:port ) )
  exit( 0 );

url = "/WebConfig/lua/auth.lua";
creds = make_array( "settings", "0310", "service", "6677" );
add_header = make_array( "Content-Type", "application/x-www-form-urlencoded; charset=UTF-8", "Cookie", "web=true" );

VULN = FALSE;
report = "It was possible to login using the following credentials:";

foreach user( keys( creds ) ) {
  pass = creds[user];

  req = http_post_put_req( port:port, url:url, data:"pw=" + pass + "&group=" + user, add_headers:add_header );
  buf = http_send_recv( port:port, data:req, bodyonly:FALSE );

  # Examples of successful authentication:
  # {"groups":["user","level1","manager","service","settings"],"r":0}
  # {"groups":["user","level1","settings"],"r":0}
  #
  # If the authentication fails, the group info will be empty:
  # {"groups":[],"r":1}
  if( '"level1"' >< buf && '"groups":[' >< buf && '"groups":[],' >!< buf ) {
    VULN = TRUE;
    report += '\n' + user + ':' + pass;
  }
}

if( VULN ) {
  report += '\n\n' + http_report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
