# Copyright (C) 2009 Christian Eric Edjenguele
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

CPE = "cpe:/a:apache:ofbiz";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.101023");
  script_version("2021-12-21T05:20:49+0000");
  script_tag(name:"last_modification", value:"2021-12-21 05:20:49 +0000 (Tue, 21 Dec 2021)");
  script_tag(name:"creation_date", value:"2009-04-25 21:03:34 +0200 (Sat, 25 Apr 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_app");

  script_tag(name:"solution_type", value:"Mitigation");

  script_name("Apache OFBiz Default Admin Credentials (HTTP)");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2009 Christian Eric Edjenguele");
  script_family("Default Accounts");
  script_dependencies("apache_ofbiz_http_detect.nasl", "gb_default_credentials_options.nasl");
  script_mandatory_keys("apache/ofbiz/http/detected");
  script_require_ports("Services/www", 8443);
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_tag(name:"summary", value:"The remote host is running Apache OFBiz with a default
  administrator username and password.");

  script_tag(name:"solution", value:"Set a strong password for the 'admin' account.");

  script_tag(name:"impact", value:"This allow an attacker to gain administrative access to the
  remote application.");

  exit(0);
}

if(get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! get_app_location( port:port, cpe:CPE, nofork:TRUE ) )
  exit( 0 );

modules = get_kb_list( "apache/ofbiz/" + port + "/modules" );
if( ! modules )
  exit( 0 );

postdata = string( "USERNAME=admin&PASSWORD=ofbiz" );
postlen = strlen( postdata );

# Sort no not report on changes on delta reports if the order is different
modules = sort( modules );

host = http_host_name( port:port );

foreach module( modules ) {

  if( module == "/" )
    module = "";

  url = module + "/control/login";
  req = string( "POST ", url, " HTTP/1.1\r\n",
                "Content-Type: application/x-www-form-urlencoded\r\n",
                "Content-Length: ", postlen , "\r\n",
                "Referer: http://", host, url, "\r\n",
                "Host: ", host,
                "\r\n\r\n",
                postdata );
  res = http_keepalive_send_recv( port:port, data:req );
  if( ! res )
    continue;

  welcomeMsg = egrep( pattern:'(Welcome THE ADMIN|THE PRIVILEGED ADMINISTRATOR|/control/logout">Logout</a></li>)', string:res );
  if( ! welcomeMsg )
    continue;

  VULN = TRUE;
  report += '\n' + http_report_vuln_url( port:port, url:url, url_only:TRUE );
}

if( VULN ) {
  report = 'It was possible to login with the default credentials "admin:ofbiz" at the following modules:\n' + report;
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
