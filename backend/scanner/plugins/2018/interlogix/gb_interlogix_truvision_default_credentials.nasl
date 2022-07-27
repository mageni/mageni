###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_interlogix_truvision_default_credentials.nasl 12900 2018-12-28 16:37:41Z tpassfeld $
#
# Interlogix TruVision Default Credentials
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
  script_oid("1.3.6.1.4.1.25623.1.0.114057");
  script_version("$Revision: 12900 $");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-12-28 17:37:41 +0100 (Fri, 28 Dec 2018) $");
  script_tag(name:"creation_date", value:"2018-12-28 17:07:10 +0100 (Fri, 28 Dec 2018)");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Default Accounts");
  script_name("Interlogix TruVision Default Credentials");
  script_dependencies("gb_interlogix_truvision_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("interlogix/truvision/detected");

  script_xref(name:"URL", value:"https://static.interlogix.com/library/1072627A%20TruVision%20IP%20Camera%20Configuration%20Manual.pdf");

  script_tag(name:"summary", value:"The remote installation of TruVision is prone to
  a default account authentication bypass vulnerability.");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain access
  to sensitive information or modify system configuration.");

  script_tag(name:"insight", value:"The installation of TruVision is lacking a proper
  password configuration, which makes critical information and actions accessible for people with knowledge
  of the default credentials.");

  script_tag(name:"vuldetect", value:"Checks if a successful login is possible.");

  script_tag(name:"solution", value:"Change the passwords for user and admin access.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");
include("http_func.inc");


CPE = "cpe:/a:interlogix:truvision";

if(!port = get_app_port(cpe: CPE)) exit(0);
if(!get_app_location(cpe: CPE, port: port)) exit(0); # nb: Unused but added to have a reference to the Detection-NVT in the GSA

creds = make_array("admin", "1234");

foreach cred(keys(creds)) {

  url = "/Login.htm";

  #command=login&username=admin&password=1234
  data = "command=login&username=" + cred + "&password=" + creds[cred];

  #Cookie: NetSuveillanceWebCookie=%7B%22username%22%3A%22admin%22%7D -> {"username":"admin"}
  auth = "NetSuveillanceWebCookie=%7B%22username%22%3A%22" + cred + "%22%7D";

  req = http_post_req(port: port, url: url, data: data, add_headers: make_array("Cookie",  auth));

  res = http_send_recv(port: port, data: req);

  if("var g_SoftWareVersion=" >< res && "var g_HardWareVersion=" >< res) {
    VULN = TRUE;
    report += '\nusername: "' + cred + '", password: "' + creds[cred] + '"';

    #var g_SoftWareVersion="V4.02.R11.31508069.12201";
    ver = eregmatch(pattern: 'var g_SoftWareVersion="V([0-9.a-zA-Z]+)";', string: res);
    if(!isnull(ver[1])) set_kb_item(name: "interlogix/truvision/version", value: ver[1]);
  }
}

if(VULN) {
  report = "It was possible to login with the following default credentials: " + report;
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
