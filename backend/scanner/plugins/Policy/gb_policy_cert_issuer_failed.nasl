###############################################################################
# OpenVAS Vulnerability Test
#
# SSL/TLS: Cert Issuer Policy Check Failed
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

# nb: Keep above the description part as it is used there
include("misc_func.inc");
include("version_func.inc");

# TODO: Remove once GVM-9 and GOS < 4.3.x is retired
# nb: includes in the description phase won't work anymore from GOS 4.2.11 (GVM TBD)
# onwards so checking for the defined_func and default to TRUE below if the funcs are undefined
if( defined_func( "get_local_gos_version" ) &&
    defined_func( "version_is_greater_equal" ) ) {
  gos_version = get_local_gos_version();
  if( strlen( gos_version ) > 0 &&
      version_is_greater_equal( version:gos_version, test_version:"4.2.4" ) ) {
    use_severity = TRUE;
  } else {
    use_severity = FALSE;
  }
} else {
  use_severity = TRUE;
}

if( OPENVAS_VERSION && version_is_greater_equal( version:OPENVAS_VERSION, test_version:"10" ) )
  use_severity = TRUE;

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140040");
  script_version("2019-05-07T10:42:32+0000");
  if( use_severity ) {
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  } else {
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  }
  script_tag(name:"last_modification", value:"2019-05-07 10:42:32 +0000 (Tue, 07 May 2019)");
  script_tag(name:"creation_date", value:"2016-11-01 10:15:30 +0100 (Tue, 01 Nov 2016)");
  script_name("SSL/TLS: Cert Issuer Policy Check Failed");
  script_category(ACT_GATHER_INFO);
  script_family("Policy");
  script_copyright("Copyright (c) 2016 Greenbone Networks GmbH");
  script_dependencies("Policy/gb_policy_cert_issuer.nasl");
  script_mandatory_keys("ssl_tls/port", "policy_cert_issuer/check_issuer", "policy_cert_issuer/run_test");

  script_tag(name:"summary", value:"This script reports if the SSL/TLS certificate is not signed by the given issuer.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include("ssl_funcs.inc");

if( ! port = get_ssl_port() ) exit( 0 );

if( ! failed = get_kb_item( "policy_cert_issuer/" + port + "/failed" ) ) exit( 0 );

issuer = get_kb_item( "policy_cert_issuer/" + port + "/issuer" );
check_issuer = get_kb_item( "policy_cert_issuer/check_issuer" );

report = 'The issuer `' + issuer + '` is not matching the given issuer `' + check_issuer  + '`.';

if( use_severity )
  security_message( port:port, data:report );
else
  log_message( port:port, data:report );
exit( 0 );
