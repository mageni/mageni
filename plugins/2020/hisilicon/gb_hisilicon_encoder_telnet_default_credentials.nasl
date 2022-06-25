# Copyright (C) 2020 Greenbone Networks GmbH
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

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.144722");
  script_version("2020-10-08T09:09:29+0000");
  script_tag(name:"last_modification", value:"2020-10-09 10:01:41 +0000 (Fri, 09 Oct 2020)");
  script_tag(name:"creation_date", value:"2020-10-08 06:50:04 +0000 (Thu, 08 Oct 2020)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2020-24218");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"Mitigation");

  script_name("HiSilicon Encoder Default Credentials (Telnet)");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Default Accounts");
  script_dependencies("telnetserver_detect_type_nd_version.nasl", "gb_default_credentials_options.nasl");
  script_require_ports("Services/telnet", 23);
  script_mandatory_keys("telnet/mult_dvr_or_radio/detected");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_tag(name:"summary", value:"HiSilicon Encoder devices are using default credentials over Telnet.");

  script_tag(name:"vuldetect", value:"Tries to login with default credentials and checks the response.");

  script_tag(name:"impact", value:"Successful exploitation would allow attackers to gain complete administrative
  access to the host.");

  script_tag(name:"affected", value:"HiSilicon Encoders. Other products might be vulnerable as well.");

  script_tag(name:"solution", value:"Change the default password for the administrative account 'root' for Telnet.");

  script_xref(name:"URL", value:"https://kojenov.com/2020-09-15-hisilicon-encoder-vulnerabilities/#root-access-via-telnet-cve-2020-24218");

  exit(0);
}

if (get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

include("dump.inc");
include("host_details.inc");
include("misc_func.inc");
include("telnet_func.inc");
include("port_service_func.inc");

port = telnet_get_port(default: 23);

if (!banner = telnet_get_banner(port: port))
  exit(0);

if ("(none) login:" >!< banner)
  exit(0);

username = "root";
passwords = make_list("neworange88888888",
                      "newsheen");

foreach password (passwords) {
  soc = open_sock_tcp(port);
  if (!soc)
    exit(0);

  banner = telnet_negotiate(socket: soc);
  if (!banner || "(none) login:" >!< banner) {
    telnet_close_socket(socket: soc);
    continue;
  }

  send(socket: soc, data: username + '\r\n');
  recv = recv(socket: soc, length: 128);
  if (!recv || "Password:" >!< recv) {
    telnet_close_socket(socket: soc, data: recv);
    continue;
  }

  send(socket: soc, data: password + '\r\n');
  recv = recv(socket: soc, length: 128);
  telnet_close_socket(socket: soc, data: recv);

  if (recv && "Welcome to HiLinux" >< recv) {
    report = 'It was possible to log in with username "' + username + '" and password "' + password + '".';
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
