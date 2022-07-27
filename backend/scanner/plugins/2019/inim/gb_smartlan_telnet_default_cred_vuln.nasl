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
  script_oid("1.3.6.1.4.1.25623.1.0.143258");
  script_version("2019-12-17T07:47:12+0000");
  script_tag(name:"last_modification", value:"2019-12-17 07:47:12 +0000 (Tue, 17 Dec 2019)");
  script_tag(name:"creation_date", value:"2019-12-17 03:16:07 +0000 (Tue, 17 Dec 2019)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_name("Inim SmartLAN Hardcoded Credentials (Telnet)");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Default Accounts");
  script_dependencies("gb_inim_smartlan_consolidation.nasl", "gb_default_credentials_options.nasl");
  script_mandatory_keys("inim/smartlan/telnet/detected");
  script_require_ports("Services/telnet", 23);
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_tag(name:"summary", value:"SmartLAN devices utilize hardcoded credentials within its Linux distribution
  image.");

  script_tag(name:"insight", value:"The devices utilize hard-coded credentials within its Linux distribution
  image. These sets of credentials are never exposed to the end-user and cannot be changed through any normal
  operation of the smart home device.");

  script_tag(name:"impact", value:"An attacker could exploit this vulnerability by logging in and gain system access");

  script_tag(name:"vuldetect", value:"The script tries to login via Telnet with the default credentials.");

  script_tag(name:"solution", value:"No known solution is available as of 17th December, 2019.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://www.zeroscience.mk/en/vulnerabilities/ZSL-2019-5546.php");

  exit(0);
}

if (get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

include("dump.inc");
include("host_details.inc");
include("misc_func.inc");
include("telnet_func.inc");

if (!port = get_app_port(cpe: CPE, service: "telnet"))
  exit(0);

if (!get_app_location(cpe: CPE, port: port))
  exit(0);

creds = make_array("root", "pass",
                   "logout", "logout");
found = make_array();

foreach user (keys(creds)) {
  soc = open_sock_tcp(port);
  if (!soc)
    continue;

  recv = telnet_negotiate(socket: soc);
  if ("login:" >< recv) {
    send(socket: soc, data: user + '\r\n');
    recv = recv(socket: soc, length: 512);
    if ("Password:" >< recv) {
      send(socket: soc, data: creds[user] + '\r\n');
      recv = recv(socket:soc, length:1024);

      if ("Login incorrect" >!< recv) {
        send(socket: soc, data: 'id\r\n');
        recv = recv(socket:soc, length:1024);
        if (recv =~ "uid=[0-9]+.*gid=[0-9]+.*")
          found[user] = creds[user];
      }
    }
  }

  close(soc);
}

foreach user (keys(found))
  report += '\nUsername: ' + user + "   Password: " + found[user];

if (report) {
  report = 'It was possible to login with the following credentials:\n' + report;
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
