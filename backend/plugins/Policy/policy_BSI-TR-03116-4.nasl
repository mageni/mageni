###############################################################################
# OpenVAS Vulnerability Test
# $Id: policy_BSI-TR-03116-4.nasl 5347 2017-02-19 09:15:55Z cfi $
#
# Policy for BSI-TR-03116-4
#
# Authors:
# Thomas Rotter <Thomas.Rotter@greenbone.net>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.96176");
  script_version("$Revision: 5347 $");
  script_tag(name:"last_modification", value:"$Date: 2017-02-19 10:15:55 +0100 (Sun, 19 Feb 2017) $");
  script_tag(name:"creation_date", value:"2016-02-18 11:22:31 +0100 (Thu, 18 Feb 2016)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("BSI-TR-03116-4 Policy");
  script_category(ACT_GATHER_INFO);
  script_family("Policy");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("secpod_ssl_ciphers.nasl");
  script_mandatory_keys("secpod_ssl_ciphers/supported_ciphers", "ssl_tls/port");
  script_add_preference(name:"Perform check:", type:"checkbox", value:"no");

  script_tag(name:"summary", value:"This Script is a test Policy for BSI-TR-03116-4");

  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("ssl_funcs.inc");
include("misc_func.inc");

pf = script_get_preference("Perform check:");
if( pf != "yes" ) exit( 0 );

set_kb_item( name:"policy/BSI-TR-03116-4/started", value:TRUE );

sslPort = get_ssl_port();
if( ! sslPort ) exit( 0 );

ciphers = get_kb_list( "secpod_ssl_ciphers/*/" + sslPort + "/supported_ciphers" );
if( ! ciphers ) exit( 0 );

check_ciphers = make_list( "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
                           "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
                           "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
                           "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                           "TLS_RSA_PSK_WITH_AES_128_CBC_SHA256",
                           "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256" );

foreach check_cipher( check_ciphers ) {
  if( in_array( search:check_cipher, array:ciphers ) ) {
    ok_ciph += check_cipher + '\n';
  }
}

if( ok_ciph ) {
  set_kb_item( name:"policy/BSI-TR-03116-4/" + sslPort + "/ok", value:ok_ciph );
  set_kb_item( name:"policy/BSI-TR-03116-4/ok", value:TRUE );
  exit( 99 );
} else {
  report = "Keiner der unter Punkt 2.1.2 geforderten Ciphers wurde auf dem System unter Port " + sslPort + " gefunden.";
  set_kb_item( name:"policy/BSI-TR-03116-4/" + sslPort + "/fail", value:report );
  set_kb_item( name:"policy/BSI-TR-03116-4/fail", value:TRUE );
  exit( 0 );
}
