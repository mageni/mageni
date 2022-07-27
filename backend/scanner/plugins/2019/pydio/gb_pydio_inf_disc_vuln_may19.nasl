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
  script_oid("1.3.6.1.4.1.25623.1.0.113403");
  script_version("2019-06-06T08:21:50+0000");
  script_tag(name:"last_modification", value:"2019-06-06 08:21:50 +0000 (Thu, 06 Jun 2019)");
  script_tag(name:"creation_date", value:"2019-06-03 11:26:33 +0200 (Mon, 03 Jun 2019)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2019-10046");

  script_name("Pydio <= 8.2.2 Information Disclosure Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_pydio_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("pydio/installed");

  script_tag(name:"summary", value:"Pydio is prone to an information disclosure vulnerability.");
  script_tag(name:"vuldetect", value:"Tries to read sensitive information.");
  script_tag(name:"insight", value:"An unauthenticated attacker can access sensitive information
  via both a POST request to /index.php and a GET request to /index.php?get_action=get_boot_conf.");
  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to read information
  for example about session timeout, license information and installed PHP libraries.");
  script_tag(name:"affected", value:"Pydio through version 8.2.2.");
  script_tag(name:"solution", value:"Update to version 8.2.3.");

  script_xref(name:"URL", value:"https://www.secureauth.com/labs/advisories/pydio-8-multiple-vulnerabilities");

  exit(0);
}

CPE = "cpe:/a:pydio:pydio";

include( "host_details.inc" );
include( "misc_func.inc" );
include( "http_func.inc" );
include( "http_keepalive.inc" );

if( ! port = get_app_port( cpe: CPE, service: "www" ) ) exit( 0 );
if( ! location = get_app_location( cpe: CPE, port: port ) ) exit( 0 );

if( location == "/" )
  location = "";

url = location + "/index.php?get_action=get_boot_conf";
buf = http_ka_recv_buf( port: port, url: url, nocache: TRUE );

vuln_url = "";

if( buf =~ '"ajxpVersion":' && buf =~ 'HTTP/[0-9]([.][0-9]+)? 200' ) {
  proto = "GET";
  vuln_url = url;
}

if( ! proto ) {
  url = location + "/index.php";
  req = http_post_req( port: port,
                       url: url,
                       data: "get_action=display_doc&doc_file=CREDITS&secure_token=",
                       add_headers: make_array( "Content-Type", "application/x-www-form-urlencoded" ) );
  buf = http_keepalive_send_recv( port: port, data: req );
  if ( buf =~ '>PHP Libraries</div>' && buf =~ 'HTTP/[0-9]([.][0-9]+)? 200' ) {
    proto = "POST";
    vuln_url = url;
  }
}

if( proto ) {
  report = "It was possible to access sensitive information with a crafted HTTP " + proto + " request to: " +
    report_vuln_url( port: port, url: vuln_url, url_only: TRUE );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
