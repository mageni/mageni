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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143259");
  script_version("2019-12-17T07:47:12+0000");
  script_tag(name:"last_modification", value:"2019-12-17 07:47:12 +0000 (Tue, 17 Dec 2019)");
  script_tag(name:"creation_date", value:"2019-12-17 03:16:07 +0000 (Tue, 17 Dec 2019)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_name("Inim SmartLAN Hardcoded Credentials (FTP)");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Default Accounts");
  script_dependencies("ftpserver_detect_type_nd_version.nasl", "gb_default_credentials_options.nasl");
  script_mandatory_keys("ftp/vftpd/detected");
  script_require_ports("Services/ftp", 21);
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_tag(name:"summary", value:"SmartLAN devices utilize hardcoded credentials within its Linux distribution
  image.");

  script_tag(name:"insight", value:"The devices utilize hard-coded credentials within its Linux distribution
  image. These sets of credentials are never exposed to the end-user and cannot be changed through any normal
  operation of the smart home device.");

  script_tag(name:"impact", value:"An attacker could exploit this vulnerability by logging in and gain system access.");

  script_tag(name:"vuldetect", value:"The script tries to login via FTP with the default credentials.");

  script_tag(name:"solution", value:"No known solution is available as of 17th December, 2019.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://www.zeroscience.mk/en/vulnerabilities/ZSL-2019-5546.php");

  exit(0);
}

if (get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

include("ftp_func.inc");

port = get_ftp_port(default: 21);
banner = get_ftp_banner(port: port);

# SmartLAN includes Virtual FTPd
if (!banner || "vftpd" >!< banner)
  exit(0);

creds = make_array("root", "pass",
                   "logout", "logout");
found = make_array();

foreach user (keys(creds)) {
  soc = ftp_open_socket(port: port);
  if (!soc)
    continue;

  if (ftp_authenticate(socket: soc, user: user, pass: creds[user]))
    found[user] = creds[user];

  ftp_close(socket: soc);
}

foreach user (keys(found))
  report += '\nUsername: ' + user + "   Password: " + found[user];

if (report) {
  report = 'It was possible to login with the following credentials:\n' + report;
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
