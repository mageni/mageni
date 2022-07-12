###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ssl_ciphers.nasl 10891 2018-08-10 12:51:28Z cfischer $
#
# SSL/TLS: Check Supported Cipher Suites
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.900234");
  script_version("$Revision: 10891 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 14:51:28 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2010-04-13 17:43:57 +0200 (Tue, 13 Apr 2010)");
  script_name("SSL/TLS: Check Supported Cipher Suites");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_dependencies("secpod_ssl_ciphers_setting.nasl", "gb_ssl_sni_supported.nasl", "gb_tls_version_get.nasl");
  script_family("SSL and TLS");
  script_mandatory_keys("ssl_tls/port");

  script_tag(name:"summary", value:"This routine connects to a SSL/TLS service and checks the quality of
  the accepted cipher suites.

  Note: Depending on the amount of services offered by this host, the routine might take good amount of time to complete,
  it is advised to increase the timeout.

  The NVT 'SSL/TLS: Report Supported Cipher Suites' (OID: 1.3.6.1.4.1.25623.1.0.802067) is able to report such timeouts.");

  script_tag(name:"qod_type", value:"remote_app");

  script_timeout(3600);

  exit(0);
}

include("mysql.inc"); # For recv_mysql_server_handshake() in open_ssl_socket()
include("misc_func.inc");
include("ssl_funcs.inc");
include("secpod_ssl_ciphers.inc");
include("byte_func.inc");

sslPort = get_ssl_port();
if( ! sslPort ) exit( 0 );

tls_type = get_kb_item( "starttls_typ/" + sslPort );

if( ! tls_versions = get_kb_list("tls_version_get/" + sslPort  + "/version") ) exit( 0 );

set_kb_item( name:"secpod_ssl_ciphers/started", value:TRUE );

if( tls_type && tls_type == "mysql" )
  check_single_cipher( tls_versions:tls_versions, sslPort:sslPort );
else
  check_all_cipher( tls_versions:tls_versions, sslPort:sslPort );

# nb: The kb entry is used to report that no timeout was happening during the runtime.
set_kb_item( name:"secpod_ssl_ciphers/" + sslPort + "/no_timeout", value:TRUE );

exit( 0 );
