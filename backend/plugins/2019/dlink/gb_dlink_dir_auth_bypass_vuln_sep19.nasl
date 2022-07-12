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
  script_oid("1.3.6.1.4.1.25623.1.0.113535");
  script_version("2019-09-30T11:07:12+0000");
  script_tag(name:"last_modification", value:"2019-09-30 11:07:12 +0000 (Mon, 30 Sep 2019)");
  script_tag(name:"creation_date", value:"2019-09-30 11:55:55 +0200 (Mon, 30 Sep 2019)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_cve_id("CVE-2019-16190");

  script_name("D-Link DIR devices Authentication Bypass Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_dlink_dsl_detect.nasl", "gb_dlink_dap_detect.nasl", "gb_dlink_dir_detect.nasl", "gb_dlink_dwr_detect.nasl");
  script_mandatory_keys("Host/is_dlink_device"); # nb: Experiences in the past have shown that various different devices might be affected
  script_require_ports("Services/www", 80);


  script_tag(name:"summary", value:"Multiple D-Link DIR devices are prone to an authentication bypass vulnerability.");
  script_tag(name:"vuldetect", value:"Tries to access sensitive pages without authentication.");
  script_tag(name:"insight", value:"The SharePort Web Access on D-Link DIR devices allows authentication bypass
  through a direct request to folder_view.php or category_view.php.");
  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to access sensitive data
  or execute php code contained in files on the target machine.");
  script_tag(name:"affected", value:"Following devices and firmwares are affected:

  - D-Link DIR-868L REVB through version 2.03

  - D-Link DIR-885L REVA through version 1.20

  - D-Link DIR-895L REVA through version 1.21

  Other devices and firmware versions may also be affected.");
  script_tag(name:"solution", value:"No known solution is available as of 30th September, 2019.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://cyberloginit.com/2019/09/10/dlink-shareport-web-access-authentication-bypass.html");

  exit(0);
}

CPE_PREFIX = "cpe:/o:d-link";

include( "host_details.inc" );
include( "misc_func.inc" );
include( "http_func.inc" );
include( "http_keepalive.inc" );

if( ! infos = get_app_port_from_cpe_prefix( cpe:CPE_PREFIX, service:"www", first_cpe_only:TRUE ) )
 exit( 0 );

port = infos["port"];
CPE  = infos["cpe"];

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

path_list = make_list ( '/folder_view.php', '/category_view.php',
                        '/webaccess/folder_view.php', '/webaccess/category_view.php' );

foreach path ( path_list ) {
  url = dir + path;

  buf = http_get_cache( port: port, item: url );

  if( buf =~ 'HTTP/1\\.[0-9] 200' &&
      ( buf =~ 'alert\\("No HardDrive Connected"\\);' || buf =~ "location.href='doc.php" ) ) {
    report = report_vuln_url( port: port, url: url );
    security_message( data: report, port: port );
    exit( 0 );
  }
}

exit( 99 );
