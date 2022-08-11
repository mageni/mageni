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

CPE_PREFIX = "cpe:/o:dsx:";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112769");
  script_version("2020-07-07T14:24:31+0000");
  script_tag(name:"last_modification", value:"2020-07-08 14:19:02 +0000 (Wed, 08 Jul 2020)");
  script_tag(name:"creation_date", value:"2020-04-06 09:47:49 +0000 (Mon, 06 Apr 2020)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"Mitigation");

  script_name("DSX Communication Devices Default Credentials (HTTP)");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2020 Simmons Foods, Inc.");
  script_family("Default Accounts");
  script_dependencies("gb_dsx_comm_devices_detect.nasl", "gb_default_credentials_options.nasl");
  script_mandatory_keys("dsx/communication_device/detected");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_tag(name:"summary", value:"The DSX communication device is configured with default credentials.");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain access
  to sensitive information or modify the system configuration.");

  script_tag(name:"insight", value:"The DSX communication device is configured with a default password, which potentially
  makes sensitive information and actions accessible for people with knowledge of the default credentials.");

  script_tag(name:"vuldetect", value:"Checks if a successful login to the DSX communication device is possible using default credentials.");

  script_tag(name:"solution", value:"Change the passwords for user and admin access.");

  exit(0);
}

if( get_kb_item( "default_credentials/disable_default_account_checks" ) )
  exit( 0 );

include("host_details.inc");
include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");

if( ! infos = get_app_port_from_cpe_prefix( cpe:CPE_PREFIX, service:"www" ) )
  exit( 0 );

port = infos["port"];
cpe  = infos["cpe"];

if( ! get_app_location( cpe:cpe, port:port ) )
  exit( 0 );

creds = make_array( "master", "master", "123456", "123456" );

host = http_host_name( dont_add_port:TRUE );
url = "/communication.html";

res = http_get_cache( item:url, port:port );
# nb: Some systems had two spaces in front of the "401".
if( ! res || res !~ "^HTTP/1\.[01]  ?401" )
  exit( 0 );

VULN = FALSE;
report = 'It was possible to login with the following default credentials: (username:password)\n';

foreach user( keys( creds ) ) {
  pass = creds[user];

  req = http_get_req( port:port, url:url, add_headers:make_array( "Authorization", "Basic " + base64( str:user + ":" + pass ) ) );
  res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

  # See note about the additional space above.
  if( res =~ "^HTTP/1\.[01]  ?200" && "DSX Access Systems, Inc." >< res && '<h1 id="dsxTitle">' >< res  ) {
    VULN = TRUE;
    report += '\n' + user + ':' + pass;
    # nb: Remember any working credentials for other authenticated vulnerability tests
    set_kb_item( name:"dsx/communication_device/credentials", value:user + ":" + pass );
  }
}

if( VULN ) {
  report += '\n\n' + http_report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
