###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_areca_raid_default_admin_credentials.nasl 11867 2018-10-12 10:48:11Z cfischer $
#
# Areca Raid Storage Manager Default Admin Credentials
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2014 Greenbone Networks GmbH
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
###############################################################################

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103921");
  script_version("$Revision: 11867 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Areca Raid Storage Manager Default Admin Credentials");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:48:11 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-03-13 12:02:06 +0200 (Thu, 13 Mar 2014)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Default Accounts");
  script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("Raid_Console/banner");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"The remote Areca Raid Storage Manager web interface is prone to a default
account authentication bypass vulnerability.");
  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain
access to sensitive information or modify system configuration.");
  script_tag(name:"vuldetect", value:"Try to login with default credentials.");
  script_tag(name:"insight", value:"It was possible to login with default credentials.");
  script_tag(name:"solution", value:"Change the password.");

  script_tag(name:"solution_type", value:"Workaround");

  exit(0);
}

include("http_func.inc");
include("misc_func.inc");

port = get_http_port( default:80 );
banner = get_http_banner( port:port );

if( "401 Unauthorized" >!< banner || 'WWW-Authenticate: Digest realm="Raid Console"' >!< banner || "nonce" >!< banner ) exit( 0 );

nonce = eregmatch(pattern:'nonce="([^"]+)', string:banner);
if(isnull(nonce[1])) {
    exit(0);
}

nonce = nonce[1];
cnonce = rand();
qop = "auth";
nc = "00000001";

ha1 = hexstr(MD5("admin:Raid Console:0000"));
ha2 = hexstr(MD5("GET:/"));
response = hexstr(MD5(string(ha1,":",nonce,":",nc,":",cnonce,":",qop,":",ha2)));

host = http_host_name(port:port);

req = 'GET / HTTP/1.1\r\n' +
      'Host: ' +  host + '\r\n' +
      'Authorization: Digest username="admin", realm="Raid Console",' +
      'nonce="' + nonce + '", uri="/",' +
      'response="' + response + '", qop=' + qop  + ', nc=' + nc  + ',' +
      'cnonce="' + cnonce + '"\r\n' +
       '\r\n';
buf = http_send_recv( port:port, data:req, bodyonly:FALSE );

if( buf =~ "HTTP/1\.. 200" && "<title>Raid Storage Manager</title>" >< buf )
{
  report = 'It was possible to login using "admin" as username and "0000" as password.\n';
  security_message(port:port, data:report);
  exit(0);
}

exit( 99 );
