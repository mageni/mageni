###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_iball_baton_150m_default_credentials.nasl 11025 2018-08-17 08:27:37Z cfischer $
#
# iBall Baton 150M Router Default Credentials
#
# Authors:
# Jan Philipp Schulte <jan.schulte@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, https://www.greenbone.net
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113013");
  script_version("$Revision: 11025 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-17 10:27:37 +0200 (Fri, 17 Aug 2018) $");
  script_tag(name:"creation_date", value:"2017-10-11 15:09:33 +0200 (Wed, 11 Oct 2017)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"Workaround");

  script_name("iBall Baton 150M Router Default Credentials");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("GoAhead-Webs/banner");

  script_tag(name:"summary", value:"The iBall Baton 150M Wireless-N Broadband Router uses default credentials, no username and 'admin' as password.");
  script_tag(name:"vuldetect", value:"The script tries to log into the Router's Web Interface using the default credentials.");
  script_tag(name:"impact", value:"Successful exploitation would allow the attacker to gain administrative control over the Router and its settings.");
  script_tag(name:"affected", value:"iBall Baton 150M Wireless-N Broadband Router");
  script_tag(name:"solution", value:"Change your password to something else.");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

port = get_http_port( default:80 );
if( ! can_host_asp( port:port ) ) exit( 0 );

content = http_get_cache( port: port, item: "/login.asp" );

if( ! ( "<title>LOGIN</title>" >< content ) ) {
  exit( 0 );
}

data = "Username=YWRtaW4%3D&Password=YWRtaW4%3D";
accept_header = "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8";
add_headers = make_array( "Cache-Control", "max-age=0", "Connection", "keep-alive" );

req = http_post_req( port: port, url: "/LoginCheck", data: data, add_headers: add_headers, accept_header: accept_header );
res = http_keepalive_send_recv( port: port, data: req );

if( "login.asp" >< res ) {
  exit( 99 );
}

else if ( "advance.asp" >< res && "302 Redirect" >< res && "Set-Cookie: ecos_pw" >< res) {
  report = "It was possible to log in to the Web Interface using the default password 'admin'.";
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
