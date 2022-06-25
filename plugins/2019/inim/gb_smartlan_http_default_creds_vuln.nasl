# Copyright (C) 2019 Greenbone Networks GmbH
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

CPE = "cpe:/a:inim:smartlan_g";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143260");
  script_version("2019-12-17T08:04:17+0000");
  script_tag(name:"last_modification", value:"2019-12-17 08:04:17 +0000 (Tue, 17 Dec 2019)");
  script_tag(name:"creation_date", value:"2019-12-17 04:51:38 +0000 (Tue, 17 Dec 2019)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"Mitigation");

  script_name("Inim SmartLAN Default Credentials Vulnerability (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Default Accounts");
  script_dependencies("gb_inim_smartlan_consolidation.nasl", "gb_default_credentials_options.nasl");
  script_mandatory_keys("inim/smartlan/http/detected");
  script_require_ports("Services/www", 8080, 443);
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_tag(name:"summary", value:"SmartLAN is prone to a default account authentication bypass vulnerability
  over HTTP(s).");

  script_tag(name:"vuldetect", value:"The script tries to login via HTTP(s) with the default credentials.");

  script_tag(name:"solution", value:"Change the password.");

  exit(0);
}

if (get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

creds = make_array("admin", "pass",
                   "user", "pass");
codes = make_list("9999", "9998", "0001");

url = dir + "/cgi-bin/web.cgi";
data = "mod=testemail&par=";

foreach user (keys(creds)) {
  foreach code (codes) {
    headers = make_array("Content-Type", "application/x-www-form-urlencoded",
                         "Cookie", "user=" + user + ";pass=" + creds[user] + ";code=" + code);
    req = http_post_req(port: port, url: url, data: data, add_headers: headers);
    res = http_keepalive_send_recv(port: port, data: req);
    if (res =~ "^HTTP/1\.[01] 200" && "no auth" >!< res && "error" >!< res)
      found += user + "    " + creds[user] + "     " + code + '\n';
  }
}

if (found) {
  report = 'It was possible to authenticate with the follwowing credentials:\n\n' +
           'Username Password Code\n' + found;
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
