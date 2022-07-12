# Copyright (C) 2020 Simmons Foods, Inc.
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108748");
  script_version("2020-04-16T11:50:24+0000");
  script_tag(name:"last_modification", value:"2020-04-17 09:53:31 +0000 (Fri, 17 Apr 2020)");
  script_tag(name:"creation_date", value:"2020-03-30 12:00:00 +0000 (Mon, 30 Mar 2020)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Kronos 4500 Time Clock FTP Default Credentials");
  script_category(ACT_ATTACK);
  script_family("Default Accounts");
  script_copyright("Copyright (C) 2020 Simmons Foods, Inc.");
  script_dependencies("ftpserver_detect_type_nd_version.nasl", "DDI_FTP_Any_User_Login.nasl", "gb_default_credentials_options.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/vxftpd/detected");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_tag(name:"summary", value:"Kronos 4500 Time Clock FTP service has default credentials set.");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain
  access to sensitive information or modify the system configuration.");

  script_tag(name:"vuldetect", value:"Connects to the FTP service and tries to login with
  default credentials.");

  script_tag(name:"solution", value:"Set or change the password for 'SuperUser' or, if possible,
  disable the default account.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

if(get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

include("ftp_func.inc");
include("host_details.inc");
include("misc_func.inc");

user = "SuperUser";
pass = "2323098716";

port = ftp_get_port(default:21);

banner = ftp_get_banner(port:port);
if(!banner || "Tornado-vxWorks" >!< banner || "FTP server ready" >!< banner)
  exit(0);

if(ftp_broken_random_login(port:port))
  exit(0);

if(!soc = ftp_open_socket(port:port))
  exit(0);

if(ftp_authenticate(socket:soc, user:user, pass:pass, skip_banner:TRUE)) {
  report = "It was possible to login using the following default credentials: " + user + ":" + pass + ".";
  security_message(port:port, data:report);
  ftp_close(socket:soc);
  exit(0);
}

ftp_close(socket:soc);
exit(99);
