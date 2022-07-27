###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ilias_default_credentials.nasl 13679 2019-02-15 08:20:11Z cfischer $
#
# Ilias Default Credentials
#
# Authors:
# Michael Martin <michael.martin@greenbone.net>
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107313");
  script_version("$Revision: 13679 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-15 09:20:11 +0100 (Fri, 15 Feb 2019) $");
  script_tag(name:"creation_date", value:"2018-05-29 14:54:24 +0200 (Tue, 29 May 2018)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_app");

  script_tag(name:"solution_type", value:"Workaround");

  script_name("Ilias Default Credentials");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Default Accounts");
  script_dependencies("gb_ilias_detect.nasl");
  script_mandatory_keys("ilias/installed");

  script_tag(name:"summary", value:"Ilias is using default administrative credentials.");
  script_tag(name:"vuldetect", value:"The script tries to log in using the default credentials.");
  script_tag(name:"insight", value:"Ilias has a default administrative account called 'root' with the password 'homer'.");
  script_tag(name:"impact", value:"If unchanged, an attacker can use the default credentials to log in and gain administrative privileges.");
  script_tag(name:"affected", value:"All Ilias versions.");
  script_tag(name:"solution", value:"Change the 'root' account's password.");

  script_xref(name:"URL", value:"https://www.ilias.de/docu/goto_docu_pg_6488_367.html");

  exit(0);
}

CPE = "cpe:/a:ilias:ilias";

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

function check_v53( port, dir ) {

  local_var port, dir, req, res, clientid, phpsessionid, data, add_headers, report;

  req = http_get( port:port, item:dir + "/" );
  res = http_keepalive_send_recv( port:port, data:req );

  clientid = http_get_cookie_from_header( buf:res, pattern:"ilClientId=([^; ]+)" );
  if( isnull( clientid ) ) return;

  phpsessionid = http_get_cookie_from_header( buf:res, pattern:"PHPSESSID=([^; ]+)" );
  if( isnull( phpsessionid ) ) return;

  data = string( "username=root&password=homer&cmd%5BdoStandardAuthentication%5D=Login" );
  add_headers = make_array( "Cookie", "ilClientId=" + clientid + ";" + "PHPSESSID=" + phpsessionid, "Content-Type", "application/x-www-form-urlencoded" );
  req = http_post_req( port:port, url:dir + "/ilias.php?lang=en&client_id=" + clientid + "&cmd=post&cmdClass=ilstartupgui&cmdNode=wr&baseClass=ilStartUpGUI&rtoken=", data:data, add_headers:add_headers );
  res = http_keepalive_send_recv( port:port, data:req );

  if( res =~ "^HTTP/1\.[01] 302" && location = http_extract_location_from_redirect( port:port, data:res ) ) {

    phpsessionid = http_get_cookie_from_header( buf:res, pattern:"PHPSESSID=([^; ]+)" );
    if( isnull( phpsessionid ) ) return;

    req = http_get_req( port:port, url:location, add_headers:make_array( "Cookie", "ilClientId=" + clientid + ";" + "PHPSESSID=" + phpsessionid ) );
    res = http_keepalive_send_recv( port:port, data:req );

    if( res =~ "^HTTP/1\.[01] 302" && location = http_extract_location_from_redirect( port:port, data:res) ) {
      req = http_get_req( port:port, url:location, add_headers:make_array( "Cookie", "ilClientId=" + clientid + ";" + "PHPSESSID=" + phpsessionid ) );
      res = http_keepalive_send_recv( port:port, data:req );
    }
  }

  if( "You have to change your initial password before you can start using ILIAS services." >< res ) {
    security_message( port:port, data:"It was possible to log in to the Web Interface using the default user 'root' with the default password 'homer'." );
    exit( 0 );
  }
  return;
}

function check_v50( port, dir ) {

  local_var port, dir, req, res, clientid, sessionid, phpsessionid, authchallenge, data, add_headers, report;

  req = http_get( port:port, item:dir + "/" );
  res = http_keepalive_send_recv( port:port, data:req );

  sessionid = http_get_cookie_from_header( buf:res, pattern:"SESSID=([^; ]+)" );
  if( isnull( sessionid ) ) return;

  clientid = http_get_cookie_from_header( buf:res, pattern:"ilClientId=([^; ]+)" );
  if( isnull( clientid ) ) return;

  phpsessionid = http_get_cookie_from_header( buf:res, pattern:"PHPSESSID=([^; ]+)" );
  if( isnull( phpsessionid ) ) return;

  data = string( "username=root&password=homer&cmd%5BshowLogin%5D=Login" );
  add_headers = make_array( "Cookie", "SESSID=" + sessionid +";" + "ilClientId=" + clientid +";" + "iltest=cookie" + ";" + "PHPSESSID=" + phpsessionid +";" +"authchallenge=" + authchallenge +";", "Content-Type", "application/x-www-form-urlencoded" );
  req = http_post_req( port:port, url:dir + "/ilias.php?lang=en&client_id=" + clientid + "&cmd=post&cmdClass=ilstartupgui&cmdNode=30&baseClass=ilStartUpGUI&rtoken=", data:data, add_headers:add_headers );
  res = http_keepalive_send_recv( port: port, data: req );
  if( res =~ "^HTTP/1\.[01] 302" && location = http_extract_location_from_redirect( port:port, data:res ) ) {

    phpsessionid = http_get_cookie_from_header( buf:res, pattern:"PHPSESSID=([^; ]+)" );
    if( isnull( phpsessionid ) ) return;

    authchallenge = http_get_cookie_from_header( buf:res, pattern:"authchallenge=([^; ]+)" );
    if( isnull( authchallenge ) ) return;

    req = http_get_req( port:port, url:location, add_headers:make_array( "Cookie", "ilClientId=" + clientid + ";"  + "PHPSESSID=" + phpsessionid + ";" + "authchallenge=" + authchallenge ) );
    res = http_keepalive_send_recv( port:port, data:req );

    if( res =~ "^HTTP/1\.[01] 302" && location = http_extract_location_from_redirect( port:port, data:res ) ) {
      req = http_get_req( port:port, url:location, add_headers:make_array( "ilClientId=" + clientid + ";" +  "PHPSESSID=" + phpsessionid +";" + "authchallenge=" + authchallenge ) );
      res = http_keepalive_send_recv( port:port, data:req );
    }
  }

  if( "Welcome to your Personal Desktop!" >< res ) {
    security_message( port:port, data:"It was possible to log in to the Web Interface using the default user 'root' with the default password 'homer'." );
    exit( 0 );
  }
  return;
}

function check_v44( port, dir ) {

  local_var port, dir, req, res, clientid, phpsessionid, authchallenge, data, add_headers, report;

  req = http_get( port:port, item:dir + "/" );
  res = http_keepalive_send_recv( port:port, data:req );

  clientid = http_get_cookie_from_header( buf:res, pattern:"ilClientId=([^; ]+)" );
  if( isnull( clientid ) ) return;

  phpsessionid = http_get_cookie_from_header( buf:res, pattern:"PHPSESSID=([^; ]+)" );
  if( isnull( phpsessionid ) ) return;

  data = string( "username=root&password=homer&cmd%5BshowLogin%5D=Login" );
  add_headers = make_array( "Cookie", "ilClientId=" + clientid +";" + "PHPSESSID=" +  phpsessionid + ";" + "iltest=cookie", "Content-Type", "application/x-www-form-urlencoded" );

  req = http_post_req( port:port, url:dir + "/ilias.php?lang=en&client_id=" + clientid + "&cmd=post&cmdClass=ilstartupgui&cmdNode=nm&baseClass=ilStartUpGUI&rtoken=", data:data, add_headers:add_headers );
  res = http_keepalive_send_recv( port:port, data:req );
  if( res =~ "^HTTP/1\.[01] 302" && location = http_extract_location_from_redirect( port:port, data:res ) ) {

    phpsessionid = http_get_cookie_from_header( buf:res, pattern:"PHPSESSID=([^; ]+)" );
    if( isnull( phpsessionid ) ) return;

    authchallenge = http_get_cookie_from_header( buf:res, pattern:"authchallenge=([^; ]+)" );
    if( isnull( authchallenge ) ) return;

    req = http_get_req( port:port, url:location, add_headers:make_array( "Cookie", "iltest=cookie" + ";" + "ilClientId=" + clientid + ";"  + "PHPSESSID=" + phpsessionid + ";" + "authchallenge=" + authchallenge ) );
    res = http_keepalive_send_recv( port:port, data:req );
  }

  if( "<h1>Welcome to your Personal Desktop!</h1>" >< res ) {
    security_message( port:port, data:"It was possible to log in to the Web Interface using the default user 'root' with the default password 'homer'." );
    exit( 0 );
  }
}

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 );
if( dir == "/" ) dir = "";

check_v53( port:port, dir:dir );
check_v50( port:port, dir:dir );
check_v44( port:port, dir:dir );

exit( 99 );
