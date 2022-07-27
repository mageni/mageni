###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_policy_tls.nasl 12662 2018-12-05 11:27:06Z cfischer $
#
# SSL/TLS: Policy Check
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH, http://www.greenbone.net
#
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
  script_oid("1.3.6.1.4.1.25623.1.0.105778");
  script_version("$Revision: 12662 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-12-05 12:27:06 +0100 (Wed, 05 Dec 2018) $");
  script_tag(name:"creation_date", value:"2016-06-28 11:57:08 +0200 (Tue, 28 Jun 2016)");
  script_name("SSL/TLS: Policy Check");
  script_category(ACT_GATHER_INFO);
  script_family("Policy");
  script_copyright("Copyright (c) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_tls_version_get.nasl");
  script_mandatory_keys("ssl_tls/port");

  script_add_preference(name:"Minimum allowed TLS version:", type:"radio", value:"TLS 1.3;TLS 1.2;TLS 1.1;TLS 1.0;SSL v3");
  script_add_preference(name:"Perform check:", type:"checkbox", value:"no");
  script_add_preference(name:"Report passed tests:", type:"checkbox", value:"no");

  script_tag(name:"summary", value:"This NVT is running SSL/TLS Policy Checks.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("byte_func.inc");
include("ssl_funcs.inc");
include("misc_func.inc");

pf = script_get_preference("Perform check:");
if( pf != "yes" )
  exit( 0 );

set_kb_item( name:"tls_policy/perform_test", value:TRUE);

rpt = script_get_preference("Report passed tests:");
if( rpt == "yes" )
  set_kb_item( name:"tls_policy/report_passed_tests", value:TRUE );

if( ! port = get_ssl_port() )
  exit( 0 );

minimum_TLS = script_get_preference("Minimum allowed TLS version:");
if( ! minimum_TLS )
  exit( 0 );

set_kb_item( name:'tls_policy/minimum_TLS', value:minimum_TLS );

supported_versions = get_kb_list( "tls_version_get/" + port + "/version" );
if( ! supported_versions )
  exit( 0 );

supported_versions = sort( supported_versions );

ssl["SSLv2"]   = SSL_v2;
ssl["SSLv3"]   = SSL_v3;
ssl["TLSv1.0"] = TLS_10;
ssl["TLSv1.1"] = TLS_11;
ssl["TLSv1.2"] = TLS_12;
ssl["TLSv1.3"] = TLS_13;

if( minimum_TLS == "SSL v3" )  mtls = SSL_v3;
if( minimum_TLS == "TLS 1.0" ) mtls = TLS_10;
if( minimum_TLS == "TLS 1.1" ) mtls = TLS_11;
if( minimum_TLS == "TLS 1.2" ) mtls = TLS_12;
if( minimum_TLS == "TLS 1.3" ) mtls = TLS_13;

foreach sv( supported_versions ) {
  if( ssl[sv] < mtls )
    policy_violating_ssl_versions += version_string[ssl[sv]] + ' ';
}

if( policy_violating_ssl_versions )
  set_kb_item( name:"tls_policy/policy_violating_ssl_versions/" + port, value:policy_violating_ssl_versions );
else
  set_kb_item( name:"tls_policy/test_passed/" + port, value:TRUE );

exit( 0 );