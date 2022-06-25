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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142866");
  script_version("2019-09-09T12:27:37+0000");
  script_tag(name:"last_modification", value:"2019-09-09 12:27:37 +0000 (Mon, 09 Sep 2019)");
  script_tag(name:"creation_date", value:"2019-09-09 08:31:33 +0000 (Mon, 09 Sep 2019)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Zyxel Access Point Hardcoded FTP Credential Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Default Accounts");
  script_dependencies("ftpserver_detect_type_nd_version.nasl", "gb_default_credentials_options.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/user_number_local_time_banner/detected");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_tag(name:"summary", value:"Zyxel access points are affected by a hardcoded FTP credential vulnerability.");

  script_tag(name:"vuldetect", value:"Check if it is possible to login with hardcoded credentials.");

  script_tag(name:"insight", value:"The FTP server can be accessed with hardcoded credentials that are embedded in
  the firmware of the AP. When the WiFi network is bound to another VLAN, an attacker can cross the network by
  fetching the credentials from the FTP server.");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain access to sensitive
  information.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://www.zyxel.com/support/hardcoded-FTP-credential-vulnerability-of-access-points.shtml");
  script_xref(name:"URL", value:"https://sec-consult.com/en/blog/advisories/hardcoded-ftp-credentials-in-zyxel-wireless-access-point-series/");

  exit(0);
}

if (get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

include("ftp_func.inc");
include("host_details.inc");

creds = make_array("devicehaecived", "1234");

port = get_ftp_port(default: 21);

if (get_kb_item("ftp/" + port + "/anonymous"))
  exit(0);

banner = get_ftp_banner(port: port);

# nb: The initial banner grabbing might have failed due to the user limit (and thus saved in the KB) but there might be some user logins free now.
if ("220-You are user number " >!< banner && "220-Local time is now" >!< banner && " users (the maximum) are already logged in, sorry" >!< banner)
  exit(0);

foreach user (keys(creds)) {
  soc = ftp_open_socket(port: port);
  if (isnull(soc))
    exit(0);

  if (ftp_authenticate(socket: soc, user: user, pass: creds[user], skip_banner: TRUE)) {
    report = 'It was possible to log in with the following hardcoded credentials: ' + user + ":" + creds[user];
    security_message(port: port, data: report);
    ftp_close(socket: soc);
    exit(0);
  }

  ftp_close(socket: soc);
}

exit(99);
