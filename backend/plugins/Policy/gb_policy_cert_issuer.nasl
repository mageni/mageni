###############################################################################
# OpenVAS Vulnerability Test
#
# SSL/TLS: Cert Issuer Policy Check
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.140038");
  script_version("2019-04-18T08:49:33+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-04-18 08:49:33 +0000 (Thu, 18 Apr 2019)");
  script_tag(name:"creation_date", value:"2016-11-01 09:34:04 +0100 (Tue, 01 Nov 2016)");
  script_name("SSL/TLS: Cert Issuer Policy Check");
  script_category(ACT_GATHER_INFO);
  script_family("Policy");
  script_copyright("Copyright (c) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_ssl_cert_chain_get.nasl");
  script_mandatory_keys("ssl_tls/port");

  script_add_preference(name:"Perform check:", type:"checkbox", value:"no");
  script_add_preference(name:"Certificate Issuer", value:"", type:"entry");
  script_add_preference(name:"Report passed tests:", type:"checkbox", value:"no");

  script_tag(name:"summary", value:"This script checks if the SSL/TLS certificate is signed by the given issuer.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("byte_func.inc");
include("ssl_funcs.inc");
include("misc_func.inc");

pf = script_get_preference("Perform check:");
if( pf != "yes" )
  exit( 0 );

set_kb_item( name:"policy_cert_issuer/run_test", value:TRUE );

check_issuer = script_get_preference("Certificate Issuer");
if( ! check_issuer )
  exit( 0 );

check_issuer = ereg_replace( pattern:'^\\s*', replace:"", string:check_issuer );
check_issuer = ereg_replace( pattern:'\\s*$', replace:"", string:check_issuer );
check_issuer = ereg_replace( pattern:'\r', replace:"", string:check_issuer );
check_issuer = ereg_replace( pattern:'\n', replace:"", string:check_issuer );

check_issuer = chomp( check_issuer );
if( ! check_issuer )
  exit( 0 );

if( ! port = get_ssl_port() )
  exit( 0 );

rpt = script_get_preference("Report passed tests:");
if( rpt == 'yes' )
  set_kb_item( name:"policy_cert_issuer/report_passed_tests", value:TRUE );

set_kb_item( name:"policy_cert_issuer/check_issuer", value:check_issuer );

server_cert = get_kb_item( "cert_chain/" + port + '/server_cert' );
if( ! server_cert )
  exit( 0 );

server_cert = base64_decode( str:server_cert );

if( ! certobj = cert_open( server_cert ) )
  exit( 0 );

if( ! issuer = cert_query( certobj, "issuer" ) )
  exit( 0 );

set_kb_item( name:"policy_cert_issuer/" + port + "/issuer", value:issuer );

if( check_issuer != issuer )
  set_kb_item( name:"policy_cert_issuer/" + port + "/failed", value:TRUE );
else
  set_kb_item( name:"policy_cert_issuer/" + port + "/passed", value:TRUE );

exit( 0 );