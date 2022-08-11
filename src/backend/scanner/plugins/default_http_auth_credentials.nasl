###############################################################################
# OpenVAS Vulnerability Test
# $Id: default_http_auth_credentials.nasl 13679 2019-02-15 08:20:11Z cfischer $
#
# HTTP Brute Force Logins With Default Credentials
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108041");
  script_version("$Revision: 13679 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2019-02-15 09:20:11 +0100 (Fri, 15 Feb 2019) $");
  script_tag(name:"creation_date", value:"2011-09-06 14:38:09 +0200 (Tue, 06 Sep 2011)");
  script_name("HTTP Brute Force Logins With Default Credentials");
  script_category(ACT_ATTACK);
  script_family("Default Accounts");
  script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl",
                      "gb_default_credentials_options.nasl", "cgi_directories.nasl"); # cgi_directories.nasl pulls in the NVTs setting a /content/auth_required
  script_require_ports("Services/www", 80);
  script_mandatory_keys("www/content/auth_required");
  script_exclude_keys("default_credentials/disable_brute_force_checks");

  script_timeout(1800);

  script_tag(name:"summary", value:"A number of known default credentials is tried for log in via HTTP Basic Auth.

  As this NVT might run into a timeout the actual reporting of this vulnerability takes place in the
  NVT 'HTTP Brute Force Logins with default Credentials Reporting' (OID: 1.3.6.1.4.1.25623.1.0.103240)");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_active");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("default_credentials.inc");

# If optimize_test = no
if( get_kb_item( "default_credentials/disable_brute_force_checks" ) ) exit( 0 );

function _check_response( res ) {

  local_var res;

  if( res && ! isnull( res ) &&
      ( res =~ "^HTTP/1\.[01] [0-9]+" ) && # Just to be sure...
      ( res !~ "^HTTP/1\.[01] 50[0234]" ) &&
      ( res !~ "^HTTP/1\.[01] 40[0138]" ) &&
      ( res !~ "^HTTP/1\.[01] 429" ) ) { #Too Many Requests (RFC 6585)
    return TRUE;
  }
  return FALSE;
}

port = get_http_port( default:80 );
host = http_host_name( dont_add_port:TRUE );

if( ! urls = http_get_kb_auth_required( port:port, host:host ) ) exit( 0 );

set_kb_item( name:"default_http_auth_credentials/started", value:TRUE );

# nb: There are various NVTs setting a /content/auth_required. This
# makes sure we're not testing URLs which are set multiple times.
urls = make_list_unique( urls );

host = http_host_name( port:port );
useragent = http_get_user_agent();

foreach url( urls ) {

  req = http_get( item:url, port:port );
  res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

  if( res !~ "^HTTP/1\.[01] 401" ) continue; # just to be sure

  c = 0;

  foreach credential( credentials ) {

    # to many successful logins. something is wrong...
    if( c > 10 ) {
      set_kb_item( name:"default_http_auth_credentials/" + port + "/too_many_logins", value:c );
      set_kb_item( name:"default_http_auth_credentials/" + port + "/no_timeout", value:TRUE );
      exit( 0 );
    }

    # Handling of user uploaded credentials which requires to escape a ';' or ':'
    # in the user/password so it doesn't interfere with our splitting below.
    credential = str_replace( string:credential, find:"\;", replace:"#sem_legacy#" );
    credential = str_replace( string:credential, find:"\:", replace:"#sem_new#" );

    user_pass_type = split( credential, sep:":", keep:FALSE );
    if( isnull( user_pass_type[0] ) || isnull( user_pass_type[1] ) ) {
      # nb: ';' was used pre r9566 but was changed to ':' as a separator as the
      # GSA is stripping ';' from the NVT description. Keeping both in here
      # for backwards compatibility with older scan configs.
      user_pass_type = split( credential, sep:";", keep:FALSE );
      if( isnull( user_pass_type[0] ) || isnull( user_pass_type[1] ) )
        continue;
    }

    # nb: Check the type defined in default_credentials.inc if the
    # credentials should be used by this NVT.
    type = user_pass_type[3];
    if( "all" >!< type && "http" >!< type ) continue;

    user = chomp( user_pass_type[0] );
    pass = chomp( user_pass_type[1] );

    user = str_replace( string:user, find:"#sem_legacy#", replace:";" );
    pass = str_replace( string:pass, find:"#sem_legacy#", replace:";" );
    user = str_replace( string:user, find:"#sem_new#", replace:":" );
    pass = str_replace( string:pass, find:"#sem_new#", replace:":" );

    if( tolower( pass ) == "none" ) pass = "";
    if( tolower( user ) == "none" ) user = "";

    userpass = user + ":" + pass;
    userpass64 = base64( str:userpass );

    req = string( "GET ", url, " HTTP/1.1\r\n",
                  "Host: ", host, "\r\n",
                  "User-Agent: ", useragent, "\r\n",
                  "Authorization: Basic ", userpass64, "\r\n",
                  "\r\n" );
    res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

    if( res =~ "^HTTP/1\.[01] 30[0-8]" ) {

      url = http_extract_location_from_redirect( port:port, data:res );

      if( url ) {

        req = http_get( item:url, port:port );
        res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

        if( res =~ "^HTTP/1\.[01] 401" ) {

          req = string( "GET ", url, " HTTP/1.1\r\n",
                        "Host: ", host, "\r\n",
                        "User-Agent: ", useragent, "\r\n",
                        "Authorization: Basic ", userpass64, "\r\n",
                        "\r\n" );
          res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

          if( _check_response( res:res ) ) {
            statuscode = egrep( pattern:"^HTTP/1\.[01] [0-9]+( |$)", string:res );
            c++;
            set_kb_item( name:"default_http_auth_credentials/" + port + "/credentials", value:url + "#-#" + user + ":" + pass + ":" + chomp( statuscode ) );
          }
        }
      }
    } else if( _check_response( res:res ) ) {
      statuscode = egrep( pattern:"^HTTP/1\.[01] [0-9]+( |$)", string:res );
      c++;
      set_kb_item( name:"default_http_auth_credentials/" + port + "/credentials", value:url + "#-#" + user + ":" + pass + ":" + chomp( statuscode ) );
    }
  }
}

# nb: Set kb entry that no timeout was happening for further reporting
set_kb_item( name:"default_http_auth_credentials/" + port + "/no_timeout", value:TRUE );

exit( 0 );
