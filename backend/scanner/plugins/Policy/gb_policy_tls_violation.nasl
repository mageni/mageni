###############################################################################
# OpenVAS Vulnerability Test
#
# SSL/TLS: Policy Check Violations
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.105780");
  script_version("2019-05-07T10:42:32+0000");
  if( use_severity ) {
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  } else {
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  }
  script_tag(name:"last_modification", value:"2019-05-07 10:42:32 +0000 (Tue, 07 May 2019)");
  script_tag(name:"creation_date", value:"2016-06-28 14:30:12 +0200 (Tue, 28 Jun 2016)");
  script_name("SSL/TLS: Policy Check Violations");
  script_category(ACT_END);
  script_family("Policy");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("Policy/gb_policy_tls.nasl");
  script_mandatory_keys("tls_policy/perform_test", "ssl_tls/port");

  script_tag(name:"summary", value:"SSL/TLS Policy Check Violations");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include("ssl_funcs.inc");

if( ! port = get_ssl_port() )
  exit( 0 );

policy_violating_ssl_versions = get_kb_item( "tls_policy/policy_violating_ssl_versions/" + port );
if( ! policy_violating_ssl_versions )
  exit( 0 );

minimum_TLS = get_kb_item( "tls_policy/minimum_TLS" );

report  = 'Minimum allowed SSL/TLS version: ' + minimum_TLS + '\n\n';
report += 'The following SSL/TLS versions are supported by the remote service and violating the SSL/TLS policy:\n\n';
report += str_replace( string:policy_violating_ssl_versions, find:" ", replace:'\n' );

if( use_severity )
  security_message( port:port, data:report );
else
  log_message( port:port, data:report );

exit( 0 );