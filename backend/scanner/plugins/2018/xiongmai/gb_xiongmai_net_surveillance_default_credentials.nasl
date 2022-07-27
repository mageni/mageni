###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_xiongmai_net_surveillance_default_credentials.nasl 14176 2019-03-14 11:29:33Z tpassfeld $
#
# Xiongmai Net Surveillance Default Credentials
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
  script_oid("1.3.6.1.4.1.25623.1.0.114039");
  script_version("$Revision: 14176 $");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2019-03-14 12:29:33 +0100 (Thu, 14 Mar 2019) $");
  script_tag(name:"creation_date", value:"2018-10-09 19:58:10 +0200 (Tue, 09 Oct 2018)");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Default Accounts");
  script_name("Xiongmai Net Surveillance Default Credentials");
  script_dependencies("gb_xiongmai_net_surveillance_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("xiongmai/net_surveillance/detected");

  script_xref(name:"URL", value:"https://www.sec-consult.com/en/blog/2018/10/millions-of-xiongmai-video-surveillance-devices-can-be-hacked-via-cloud-feature-xmeye-p2p-cloud/");
  script_xref(name:"URL", value:"https://krebsonsecurity.com/tag/xc3511/");

  script_tag(name:"summary", value:"The remote installation of Xiongmai Net Surveillance is prone to
  a default account authentication bypass vulnerability.");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain access
  to sensitive information or modify system configuration.");

  script_tag(name:"insight", value:"The installation of Xiongmai Net Surveillance is lacking a proper
  password configuration, which makes critical information and actions accessible for people with knowledge
  of the default credentials.");

  script_tag(name:"vuldetect", value:"Checks if a successful login to Xiongmai Net Surveillance is possible.");

  script_tag(name:"solution", value:"Change the passwords for user and admin access.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("misc_func.inc");

CPE = "cpe:/a:xiongmai:net_surveillance";

if(!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if(!get_app_location(cpe: CPE, port: port)) # nb: Unused but added to have a reference to the Detection-NVT in the GSA
  exit(0);

creds = make_array("admin", "",
                   "default", "tluafed",
                   "root", "xc3511");

url = "/Login.htm";

foreach username(keys(creds)) {

  password = creds[username];
  auth_cookie = "NetSuveillanceWebCookie=%7B%22username%22%3A%22" + username + "%22%7D";
  data = "command=login&username=" + username + "&password=" + password;

  req = http_post_req(port: port,
                      url: url,
                      data: data,
                      add_headers: make_array("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
                                              "Cookie", auth_cookie));

  res = http_keepalive_send_recv(port: port, data: req);

  if("var g_SoftWareVersion=" >< res && 'failedinfo="Log in failed!"' >!< res) {
    VULN = TRUE;
    if(!password)
      password = "<no/empty password>";
    report += '\n' + username + ':' + password;
  }
}

if(VULN) {
  report = 'It was possible to login with the following default credentials (username:password):\n' + report;
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
