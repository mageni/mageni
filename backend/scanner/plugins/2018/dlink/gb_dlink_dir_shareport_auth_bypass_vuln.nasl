###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dlink_dir_shareport_auth_bypass_vuln.nasl 13450 2019-02-05 03:52:29Z ckuersteiner $
#
# D-Link DIR Routers SharePort Authentication Bypass Vulnerability
#
# Authors:
# Jan Philipp Schulte <jan.schulte@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, https://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113146");
  script_version("2019-04-01T07:47:16+0000");
  script_tag(name:"last_modification", value:"2019-04-01 07:47:16 +0000 (Mon, 01 Apr 2019)");
  script_tag(name:"creation_date", value:"2018-03-29 09:53:55 +0200 (Thu, 29 Mar 2018)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_app");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_cve_id("CVE-2018-9032");

  script_name("D-Link DIR Routers SharePort Authentication Bypass Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_dlink_dir_detect.nasl");
  script_require_ports("Services/www", 80, 8080, 8181); # D-Link VTs normally use 8080, but Shodan has more than ten times the results with 8181
  script_mandatory_keys("Host/is_dlink_dir_device"); # TBD: Check all D-Link devices like in others?

  script_tag(name:"summary", value:"D-Link DIR Routers are prone to Authentication Bypass Vulnerability.");

  script_tag(name:"vuldetect", value:"The script tries to access protected information without authentication.");

  script_tag(name:"insight", value:"The directories '/category_view.php' and '/folder_view.php' can be accessed directly without authentication.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to access information about the target system
  that would normally require authentication.");

  script_tag(name:"affected", value:"D-Link DIR Routers with SharePort functionality. Firmware versions through 2.06.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
  Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove
  the product or replace the product by another one.");

  script_xref(name:"URL", value:"https://www.youtube.com/watch?v=Wmm4p8znS3s");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/44378");

  exit(0);
}

CPE_PREFIX = 'cpe:/o:d-link';

include( "host_details.inc" );
include( "http_func.inc" );
include( "http_keepalive.inc" );

if (!infos = get_app_port_from_cpe_prefix(cpe: CPE_PREFIX, service: "www", first_cpe_only: TRUE))
  exit( 0 );

port = infos["port"];
CPE = infos["cpe"];

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

foreach vuln_file (make_list("/folder_view.php", "/category_view.php")) {

  url = dir + vuln_file;
  req = http_get( port: port, item: url );
  res = http_keepalive_send_recv( port: port, data: req );

  if( res && res =~ "^HTTP/1\.[01] 200" && res =~ "<title>SharePort Web Access</title>" && res =~ 'href="webfile_css/layout.css"' ) {
    report = report_vuln_url( port: port, url: url );
    security_message( data: report, port: port );
    exit( 0 );
  }
}

exit( 99 );
