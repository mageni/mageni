###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_tls_version.nasl 11665 2018-09-28 07:14:18Z cfischer $
#
# SSL/TLS: Version Detection Report
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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
  script_oid("1.3.6.1.4.1.25623.1.0.103823");
  script_version("$Revision: 11665 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-28 09:14:18 +0200 (Fri, 28 Sep 2018) $");
  script_tag(name:"creation_date", value:"2013-10-29 12:36:43 +0100 (Tue, 29 Oct 2013)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("SSL/TLS: Version Detection Report");
  script_category(ACT_END);
  script_family("SSL and TLS");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("secpod_ssl_ciphers.nasl");
  script_mandatory_keys("ssl_tls/port");
  script_add_preference(name:"Report TLS version", type:"checkbox", value:"no");

  script_tag(name:"summary", value:"This script reports the detected SSL/TLS versions.");

  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("ssl_funcs.inc");
include("host_details.inc");
include("byte_func.inc");
include("misc_func.inc");
include("http_func.inc"); # For make_list_unique()

function get_tls_app( port ) {

  local_var port, host_details, host_detail, host_values, oid, ports, p, cpe_str;

  host_details = get_kb_list( "HostDetails/NVT/*" );

  if( ! host_details ) return;

  foreach host_detail( keys( host_details ) ) {

    if( "cpe:/" >< host_detail ) {

      host_values = split( host_detail, sep:"/", keep:FALSE );

      if( isnull( host_values[2] ) ) continue;
      oid = host_values[2];

      ports = get_kb_list( "HostDetails/NVT/" + oid + "/port" ); # don't use get_kb_item(), because this could fork.
      if( ! ports ) continue;

      foreach p( ports ) {
        if( p == port ) {
          if( host_values[4] >!< cpe_str ) {
            cpe_str += 'cpe:/' +  host_values[4] + ';';
          }
        }
      }
    }
  }

  if( strlen( cpe_str ) ) {
    # Remove ending ";"
    cpe_str = ereg_replace( string:cpe_str, pattern:"(;)$", replace:"" );
    return cpe_str;
  }
}

function get_port_ciphers( port ) {

  local_var port, ret_ciphers, ciphers, cipher;

  ret_ciphers = '';

  if( ! port ) return;

  ciphers = get_kb_list( "secpod_ssl_ciphers/*/" + port + "/supported_ciphers" );
  if( ! ciphers ) return;

  # Make unique and sort to not report changes on delta reports if just the order is different
  ciphers = make_list_unique( ciphers );
  ciphers = sort( ciphers );

  foreach cipher( ciphers ) {
    ret_ciphers += cipher + ';';
  }

  # Remove ending ";"
  ret_ciphers = ereg_replace( string:ret_ciphers, pattern:"(;)$", replace:"" );

  return ret_ciphers;

}

enable_log = script_get_preference( "Report TLS version" );

ports = get_kb_list( "ssl_tls/port" );
if( ! ports ) exit( 0 );

foreach port( ports ) {

  sup_tls = '';
  cpe = '';

  versions = get_kb_list( "tls_version_get/" + port + "/version" );
  if( ! versions ) continue;
  foreach vers ( versions ) {
    set_kb_item( name:"tls_version/" + port + "/version", value:vers );
    sup_tls += vers + ';';
    register_host_detail( name:"TLS/port", value:port, desc:"SSL/TLS: Version Detection Report" );
    register_host_detail( name:"TLS/" + port, value:vers, desc:"SSL/TLS: Version Detection Report" );
  }

  if( strlen( sup_tls ) ) {
    # Remove ending ";"
    sup_tls = ereg_replace( string:sup_tls, pattern:"(;)$", replace:"" );
    supported_tls[port] = sup_tls;
  }
}

if( 'yes' >!< enable_log ) exit( 0 );

if( supported_tls ) {

  host = get_host_name();
  ip = get_host_ip();
  #TBD: Report ciphers for each SSL/TLS Version separately?
  text = 'IP,Host,Port,SSL/TLS-Version,Ciphers,Application-CPE\n';

  foreach p( keys( supported_tls ) ) {

    text += ip + ',' + host + ',' +  p + ',' + supported_tls[p];

    ciphers = get_port_ciphers( port:p );

    if( ciphers )
      text += ',' + ciphers;

    cpe = get_tls_app( port:p );

    if( cpe ) {
      text += ',' + cpe + '\n';
    } else {
      text += '\n';
    }

    text = ereg_replace( string:text, pattern:'\n\n', replace:'\n' );

    report = TRUE;
  }

  if( report ) {
    log_message( port:0, data:text );
    exit( 0 );
  }
}

exit( 0 );
