###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubnt_unifi_video_default_credentials.nasl 12830 2018-12-18 19:42:17Z tpassfeld $
#
# Ubiquiti Networks Unifi Video Default Credentials
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
  script_oid("1.3.6.1.4.1.25623.1.0.114049");
  script_version("$Revision: 12830 $");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:C/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-12-18 20:42:17 +0100 (Tue, 18 Dec 2018) $");
  script_tag(name:"creation_date", value:"2018-12-17 19:08:14 +0100 (Mon, 17 Dec 2018)");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Default Accounts");
  script_name("Ubiquiti Networks Unifi Video Default Credentials");
  script_dependencies("gb_ubnt_unifi_video_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("ubnt/unifi_video/detected");

  script_xref(name:"URL", value:"https://customvideosecurity.com/research/blog/default-passwords-for-most-ip-network-camera-brands/");

  script_tag(name:"summary", value:"The remote installation of Unifi Video is prone to
  a default account authentication bypass vulnerability.");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain access
  to sensitive information or modify system configuration.");

  script_tag(name:"insight", value:"The installation of Unifi Video is lacking a proper
  password configuration, which makes critical information and actions accessible for people with knowledge
  of the default credentials.");

  script_tag(name:"vuldetect", value:"Checks if a successful login to Unifi Video is possible.");

  script_tag(name:"solution", value:"Change the passwords for user and admin access.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");
include("http_func.inc");


CPE = "cpe:/a:ubnt:unifi_video";

if(!port = get_app_port(cpe: CPE)) exit(0);
if(!get_app_location(cpe: CPE, port: port)) exit(0); # nb: Unused but added to have a reference to the Detection-NVT in the GSA

creds = make_array("ubnt", "ubnt",
                   "root", "ubnt",
                   "admin", "admin");

#Host type is one of the following:
#Session; Portal; NoSessionEmail; NoSession
#It is logically guaranteed to not be null at this point in time, so no further check is required.
hostType = get_kb_item("ubnt/unifi_video/hostType");

foreach cred(keys(creds)) {

  if(hostType == "NoSession") {

    url = "/api/1.1/login";

    #{"username":"ubnt","password":"ubnt"}
    data = '{"username":"' + cred + '","password":"' + creds[cred] + '"}';

    req = http_post_req(port: port, url: url, data: data, add_headers: make_array("Accept-Encoding", "gzip, deflate",
                                                                                  "DNT", "1",
                                                                                  "Content-Type", "application/json",
                                                                                  "Accept", "application/json, text/plain, */*"));
  }
  else if(hostType == "Session") {

    url = "/api/2.0/login";

    #Initial request to acquire the sessionID
    req =  http_get_req(port: port, url: url, add_headers: make_array("Accept-Encoding", "gzip, deflate",
                                                                      "Content-Type", "application/json",
                                                                      "Accept", "application/json, text/javascript, */*; q=0.01",
                                                                      "X-Requested-With", "XMLHttpRequest"));
    res = http_send_recv(port: port, data: req);

    sessID = eregmatch(pattern: "Set-Cookie:\s*JSESSIONID_AV=([0-9a-zA-Z]+);", string: res);
    if(isnull(sessID[1])) continue;
    sessionID = sessID[1];

    #{"username":"ubnt","password":"ubnt"}
    data = '{"username":"' + cred + '","password":"' + creds[cred] + '"}';

    req = http_post_req(port: port, url: url, data: data, add_headers: make_array("Accept-Encoding", "gzip, deflate",
                                                                                  "Content-Type", "application/json",
                                                                                  "Accept", "application/json, text/javascript, */*; q=0.01",
                                                                                  "X-Requested-With", "XMLHttpRequest",
                                                                                  "Cookie", "JSESSIONID_AV=" + sessionID));
  }
  else if(hostType == "NoSessionEmail") {

    url = "/api/2.0/login";

    #An email address is expected, but maybe the default credentials work anyways.
    #{"email":"ubnt","password":"ubnt"}
    data = '{"email":"' + cred + '","password":"' + creds[cred] + '"}';

    req = http_post_req(port: port, url: url, data: data, add_headers: make_array("Accept-Encoding", "gzip, deflate",
                                                                                  "Content-Type", "application/json",
                                                                                  "Accept", "application/json, text/javascript, */*; q=0.01",
                                                                                  "X-Requested-With", "XMLHttpRequest"));
  }
  else exit(99); #Portal just redirects to another host on the internal network or to itself on another port

  res = http_send_recv(port: port, data: req);

  if("authId=" >< res) {
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
