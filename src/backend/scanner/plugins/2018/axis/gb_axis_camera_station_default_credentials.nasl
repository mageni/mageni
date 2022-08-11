###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_axis_camera_station_default_credentials.nasl 11328 2018-09-11 12:32:47Z tpassfeld $
#
# Axis Camera Station Default Credentials
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
  script_oid("1.3.6.1.4.1.25623.1.0.114028");
  script_version("$Revision: 11328 $");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-09-11 14:32:47 +0200 (Tue, 11 Sep 2018) $");
  script_tag(name:"creation_date", value:"2018-08-29 12:41:33 +0200 (Wed, 29 Aug 2018)");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Default Accounts");
  script_name("Axis Camera Station Default Credentials");
  script_dependencies("gb_axis_camera_station_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("axis/camerastation/detected");

  script_xref(name:"URL", value:"https://customvideosecurity.com/blog/tag/default-password-axis/");

  script_tag(name:"summary", value:"The remote installation of Axis Camera Station is prone to
  a default account authentication bypass vulnerability.");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain access
  to sensitive information or modify system configuration.");

  script_tag(name:"insight", value:"The installation of Axis Camera Station is lacking a proper
  password configuration, which makes critical information and actions accessible for people with knowledge
  of the default credentials.");

  script_tag(name:"vuldetect", value:"Checks if a successful login to Axis Camera Station is possible.");

  script_tag(name:"solution", value:"Change the passwords for user and admin access.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");

CPE = "cpe:/a:axis:camera_station";

if(!port = get_app_port(cpe: CPE)) exit(0);
if(!get_app_location(cpe: CPE, port: port)) exit(0); # nb: Unused but added to have a reference to the Detection-NVT

creds = make_array("root", "pass");

url = "/axis-cgi/param.cgi";
data = "action=listdefinitions&listformat=xmlschema&responseformat=rfc&responsecharset=utf8&group=GuardTour";

foreach cred(keys(creds)) {

  req1 = http_post_req(port: port, url: url, data: data, add_headers: make_array("Accept-Encoding", "gzip, deflate",
                                                                                 "Content-Type", "application/json; charset=utf-8",
                                                                                 "Axis-Orig-Sw", "true",
                                                                                 "X-Requested-With", "XMLHttpRequest"));
  res1 = http_keepalive_send_recv(port: port, data: req1);

  #Digest realm="AXIS_ACCC8E59BF16", nonce="cE7MlfV0BQA=3d81636877c1a2d7a335f9d39bb9e90a45396eeb", algorithm=MD5, qop="auth"
  info = eregmatch(pattern: 'Digest realm="([^"]+)", nonce="([^"]+)", algorithm=MD5', string: res1);
  if(isnull(info[1]) || isnull(info[2])) continue;
  realm = info[1];
  nonce = info[2];

  #Digest authentication according to the standard showcased here: https://code-maze.com/http-series-part-4/#digestauth
  cnonce = rand_str(charset:"abcdefghijklmnopqrstuvwxyz0123456789", length:16);
  qop = "auth";
  nc = "00000001";
  ha1 = hexstr(MD5(string(cred, ":", realm, ":", creds[cred])));
  ha2 = hexstr(MD5(string("POST:", url)));
  response = hexstr(MD5(string(ha1, ":", nonce, ":", nc, ":", cnonce, ":", qop, ":", ha2)));

  auth = 'Digest username="' + cred + '", realm="' + realm + '", nonce="' + nonce + '", uri="' + url + '", algorithm=MD5, response="' + response + '", qop=' + qop + ', nc=' + nc + ', cnonce="' + cnonce + '"';

  req2 = http_post_req(port: port, url: url, data: data, add_headers: make_array("Accept-Encoding", "gzip, deflate",
                                                                                 "Content-Type", "application/json; charset=utf-8",
                                                                                 "Axis-Orig-Sw", "true",
                                                                                 "X-Requested-With", "XMLHttpRequest",
                                                                                 "Authorization", auth));
  res2 = http_keepalive_send_recv(port: port, data: req2);

  if("axis" >< res2 && "<firmwareVersion>" >< res2) {
    VULN = TRUE;
    report += '\nusername: "' + cred + '", password: "' + creds[cred] + '"';

    #<firmwareVersion>8.20.1</firmwareVersion>
    firmVer = eregmatch(pattern: "<firmwareVersion>([0-9.]+)</firmwareVersion>", string: res2);

    if(firmVer[1]) set_kb_item(name: "axis/camerastation/firmware/version", value: firmVer[1]);
  }


}

if(VULN) {
  report = "It was possible to login with the following default credentials: " + report;
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
