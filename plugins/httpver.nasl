###############################################################################
# OpenVAS Vulnerability Test
# $Id: httpver.nasl 13659 2019-02-14 08:34:21Z cfischer $
#
# HTTP-Version Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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
  script_oid("1.3.6.1.4.1.25623.1.0.100034");
  script_version("$Revision: 13659 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-14 09:34:21 +0100 (Thu, 14 Feb 2019) $");
  script_tag(name:"creation_date", value:"2009-03-10 08:40:52 +0100 (Tue, 10 Mar 2009)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("HTTP-Version Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Service detection");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  # nb: Don't add a dependency to http_version.nasl to avoid cyclic dependency to embedded_web_server_detect.nasl
  script_dependencies("find_service.nasl", "find_service1.nasl", "find_service2.nasl", "apache_SSL_complain.nasl",
                      "sw_ssl_cert_get_hostname.nasl"); # To catch and inject any additional hostnames early in the dependency chain.
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Check the HTTP-Version");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");

# This function makes sure that we're not setting two different
# HTTP versions for the same port. This could happen if we have
# multiple vhosts and some of the checks below failed. Instead
# of setting a new HTTP version or overwriting a previous detected
# one the highest detected HTTP version is kept.
function set_http_ver_nd_exit( port, httpver ) {

  local_var port, httpver, _httpver;

  _httpver = get_kb_item( "http/" + port );
  if( ! _httpver ) {
    set_kb_item( name:"http/" + port, value:httpver );
    exit( 0 );
  }

  if( int( httpver ) > int( _httpver ) )
    replace_kb_item( name:"http/" + port, value:httpver );

  exit( 0 );
}

port = get_http_port( default:80 );

# nb: Always keep http_host_name() before http_open_socket() as the first
# could fork with multiple vhosts and the child's would share the same
# socket causing race conditions and similar.
host = http_host_name( port:port );
host_plain = http_host_name( dont_add_port:TRUE );

soc = http_open_socket( port );
if( ! soc ) exit( 0 );

useragent = http_get_user_agent();
req = string( "GET / HTTP/1.1\r\n",
              "Host: ", host, "\r\n",
              "User-Agent: ", useragent, "\r\n",
              "Accept: */*\r\n",
              "Connection: close\r\n",
              "\r\n" );
send( socket:soc, data:req );
buf = http_recv_headers2( socket:soc );
http_close_socket( soc );
if( isnull( buf ) || buf == "" ) exit( 0 );

# https://en.wikipedia.org/wiki/List_of_HTTP_status_codes#5xx_Server_error
# Don't check for 505 as some servers might return 505 for a HTTP/1.1 request if they support only 1.0
# TBD: Other 50x to check here? What about servers which might throw a 500 on "/" but not on subdirs / files?
if( buf =~ "^HTTP/1\.[0-1] 50[0-4]" ) {
  # TBD: Since the beginning the KB key below was set with an ending "/" and in no404.nasl it was set without it
  set_kb_item( name:"www/" + host_plain + "/" + port + "/is_broken/", value:TRUE );
  set_kb_item( name:"www/" + host_plain + "/" + port + "/is_broken/reason", value:"50x" );
  exit( 0 );
}

else if( buf =~ "^HTTP/1\.1 [1-5][0-9][0-9]" ) {
  set_http_ver_nd_exit( port:port, httpver:"11" );
}

else if( buf =~ "^HTTP/1\.0 [1-5][0-9][0-9]" ) {
  set_http_ver_nd_exit( port:port, httpver:"10" );
}

else {

  soc = http_open_socket( port );
  if( ! soc ) exit( 0 );
  req = string( "GET / HTTP/1.0\r\n",
                "\r\n" );
  send( socket:soc, data:req );
  buf = http_recv_headers2( socket:soc );
  http_close_socket( soc );
  if( isnull( buf ) || buf == "" ) exit( 0 );

  # https://en.wikipedia.org/wiki/List_of_HTTP_status_codes#5xx_Server_error
  # Don't check for 505 as some servers might return 505 for a HTTP/1.0 request if they support only 0.9
  # TBD: Other 50x to check here? What about servers which might throw a 500 on "/" but not on subdirs / files?
  if( buf =~ "^HTTP/1\.[0-1] 50[0-4]" ) {
    # TBD: Since the beginning the KB key below was set with an ending "/" and in no404.nasl it was set without it
    set_kb_item( name:"www/" + host_plain + "/" + port + "/is_broken/", value:TRUE );
    set_kb_item( name:"www/" + host_plain + "/" + port + "/is_broken/reason", value:"50x" );
    exit( 0 );
  }

  else if( buf =~ "^HTTP/1\.0 [1-5][0-9][0-9]" ) {
    set_http_ver_nd_exit( port:port, httpver:"10" );
  }
}

## if all fail set to 1.0 anyway
set_http_ver_nd_exit( port:port, httpver:"10" );
