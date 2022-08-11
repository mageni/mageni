###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_policy_tls_passed.nasl 12662 2018-12-05 11:27:06Z cfischer $
#
# SSL/TLS: Policy Check OK
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
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
  script_oid("1.3.6.1.4.1.25623.1.0.105781");
  script_version("$Revision: 12662 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-12-05 12:27:06 +0100 (Wed, 05 Dec 2018) $");
  script_tag(name:"creation_date", value:"2016-06-28 15:37:57 +0200 (Tue, 28 Jun 2016)");
  script_name("SSL/TLS: Policy Check OK");
  script_category(ACT_END);
  script_family("Policy");
  script_copyright("Copyright (c) 2016 Greenbone Networks GmbH");
  script_dependencies("Policy/gb_policy_tls.nasl");
  script_mandatory_keys("tls_policy/perform_test", "tls_policy/report_passed_tests", "ssl_tls/port");

  script_tag(name:"summary", value:"Shows all supported SSL/TLS versions");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("ssl_funcs.inc");

if( ! port = get_ssl_port() )
  exit( 0 );

if( ! passed = get_kb_item( "tls_policy/test_passed/" + port ) )
  exit( 0 );

minimum_TLS = get_kb_item( "tls_policy/minimum_TLS" );

supported_versions = get_kb_list( "tls_version_get/" + port + "/version" );

report  = 'Minimum allowed TLS version: ' + minimum_TLS + '\n\n';
report += 'The following SSL/TLS versions are supported by the remote service:\n\n';

foreach sv( sort( supported_versions ) )
  report += sv + '\n';

report += '\nSSL/TLS policy test passed.';

log_message( port:port, data:report );
exit( 0 );