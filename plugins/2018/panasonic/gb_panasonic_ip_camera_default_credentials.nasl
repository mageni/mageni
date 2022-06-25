###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_panasonic_ip_camera_default_credentials.nasl 12234 2018-11-06 19:10:07Z tpassfeld $
#
# Panasonic IP Camera Default Credentials
#
# Authors:
# Thorsten Passfeld <thorsten.passfeld@greenbone.net>
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.114045");
  script_version("$Revision: 12234 $");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-11-06 20:10:07 +0100 (Tue, 06 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-11-05 22:52:36 +0100 (Mon, 05 Nov 2018)");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Default Accounts");
  script_name("Panasonic IP Camera Default Credentials");
  script_dependencies("gb_panasonic_ip_camera_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("panasonic/ip_camera/detected");

  script_xref(name:"URL", value:"https://customvideosecurity.com/blog/tag/default-password-axis/");

  script_tag(name:"summary", value:"The remote installation of Panasonic's IP camera software is prone to
  a default account authentication bypass vulnerability.");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain access
  to sensitive information or modify system configuration.");

  script_tag(name:"insight", value:"The installation of Panasonic's IP camera software is lacking a proper
  password configuration, which makes critical information and actions accessible for people with knowledge
  of the default credentials.");

  script_tag(name:"vuldetect", value:"Checks if a successful login to Panasonic's IP camera software is possible.");

  script_tag(name:"solution", value:"Change the passwords for user and admin access.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");

CPE = "cpe:/a:panasonic:ip_camera";

if(!port = get_app_port(cpe: CPE)) exit(0);
if(!get_app_location(cpe: CPE, port: port)) exit(0); # nb: Unused but added to have a reference to the Detection-NVT

#Most common credentials according to: https://www.cleancss.com/router-default/Panasonic/Network_Camera
creds = make_array("admin", "12345",
                   "", "1234",
                   "admin1", "password",
                   "root", "1234");

url = "/admin/index.html?Language=0";

foreach cred(keys(creds)) {

  req = http_get_req(port: port, url: url, add_headers: make_array("Accept-Encoding", "gzip, deflate",
                                                                   "Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8"));

  res = http_keepalive_send_recv(port: port, data: req);

  #WWW-Authenticate: Basic realm="Panasonic network device"
  #WWW-Authenticate: Digest realm="Panasonic network device", nonce="f59ec912d10650340f08e7d9f3b21cf2", stale="false", algorithm="MD5", qop="auth"
  info = eregmatch(pattern: 'Digest realm="([^"]+)", nonce="([^"]+)",', string: res);
  if(isnull(info[1]) || isnull(info[2])) continue;
  realm = info[1];
  nonce = info[2];

  #Digest authentication according to the standard showcased here: https://code-maze.com/http-series-part-4/#digestauth
  cnonce = rand_str(charset:"abcdefghijklmnopqrstuvwxyz0123456789", length:16);
  qop = "auth";
  nc = "00000001";
  ha1 = hexstr(MD5(string(cred, ":", realm, ":", creds[cred])));
  ha2 = hexstr(MD5(string("GET:", url)));
  response = hexstr(MD5(string(ha1, ":", nonce, ":", nc, ":", cnonce, ":", qop, ":", ha2)));

  #Digest username="admin", realm="Panasonic network device", nonce="ed99063f6b0315de902691760a6e51c7", uri="/admin/index.html?Language=0",
  #algorithm=MD5, response="cdaf705dfd5ca6945f76cb3240795191", qop=auth, nc=00000001, cnonce="b707420cab492503"
  auth = 'Digest username="' + cred + '", realm="' + realm + '", nonce="' + nonce + '", uri="' + url + '", algorithm=MD5, response="' + response + '", qop=' + qop + ', nc=' + nc + ', cnonce="' + cnonce + '"';

  req = http_get_req(port: port, url: url, add_headers: make_array("Accept-Encoding", "gzip, deflate",
                                                                   "Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
                                                                   "Authorization", auth));

  res = http_keepalive_send_recv(port: port, data: req);

  if('<html lang="en" oncontextmenu="return false">' >< res || 'alert(cmsg_show(' >< res) {
    VULN = TRUE;
    report += '\nusername: "' + cred + '", password: "' + creds[cred] + '"';
  }


}

if(VULN) {
  report = "It was possible to login with the following default credentials: " + report;
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
