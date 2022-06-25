###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_https_only_weak_ciphers.nasl 5232 2017-02-08 11:56:44Z antu123 $
#
# SSL/TLS: Report Vulnerable Cipher Suites for HTTPS
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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
  script_oid("1.3.6.1.4.1.25623.1.0.108031");
  script_version("$Revision: 5232 $");
  script_cve_id("CVE-2016-2183", "CVE-2016-6329");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-02-08 12:56:44 +0100 (Wed, 08 Feb 2017) $");
  script_tag(name:"creation_date", value:"2016-12-22 11:00:00 +0100 (Thu, 22 Dec 2016)");
  script_name("SSL/TLS: Report Vulnerable Cipher Suites for HTTPS");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2016 Greenbone Networks GmbH");
  script_family("SSL and TLS");
  script_dependencies("secpod_ssl_ciphers.nasl");
  script_require_ports("Services/www", 443);
  script_mandatory_keys("secpod_ssl_ciphers/supported_ciphers", "ssl_tls/port");

  script_xref(name:"URL", value:"https://bettercrypto.org/");
  script_xref(name:"URL", value:"https://mozilla.github.io/server-side-tls/ssl-config-generator/");
  script_xref(name:"URL", value:"https://sweet32.info/");

  script_tag(name:"summary", value:"This routine reports all SSL/TLS cipher suites accepted by a service
  where attack vectors exists only on HTTPS services.");

  script_tag(name:"solution", value:"The configuration of this services should be changed so
  that it does not accept the listed cipher suites anymore.

  Please see the references for more resources supporting you with this task.");

  script_tag(name:"insight", value:"These rules are applied for the evaluation of the vulnerable cipher suites:

  - 64-bit block cipher 3DES vulnerable to the SWEET32 attack (CVE-2016-2183).");

  script_tag(name:"affected", value:"Services accepting vulnerable SSL/TLS cipher suites via HTTPS.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("http_func.inc");

cipherText = "'Vulnerable' cipher suites";

port = get_http_port( default:443, ignore_broken:TRUE, ignore_cgi_disabled:TRUE );

## Exit on non-ssl http port
if( get_port_transport( port ) < ENCAPS_SSLv23 ) exit( 0 );

sup_ssl = get_kb_item( "tls/supported/" + port );
if( ! sup_ssl ) exit( 0 );

if( "SSLv3" >< sup_ssl ) {
  sslv3CipherList = get_kb_list( "secpod_ssl_ciphers/sslv3/" + port + "/supported_ciphers" );

  if( ! isnull( sslv3CipherList ) ) {

    # Sort to not report changes on delta reports if just the order is different
    sslv3CipherList = sort( sslv3CipherList );

    foreach sslv3Cipher( sslv3CipherList ) {
      if( sslv3Cipher =~ "^TLS_.*_3?DES_.*" ) {
        sslv3Vuln = TRUE;
        sslv3tmpReport += sslv3Cipher + ' (SWEET32)\n';
      }
    }

    if( sslv3Vuln ) {
      report += cipherText +' accepted by this service via the SSLv3 protocol:\n\n' + sslv3tmpReport + '\n';
    }
  }
}

if( "TLSv1.0" >< sup_ssl ) {
  tlsv1_0CipherList = get_kb_list( "secpod_ssl_ciphers/tlsv1/" + port + "/supported_ciphers" );

  if( ! isnull( tlsv1_0CipherList ) ) {

    # Sort to not report changes on delta reports if just the order is different
    tlsv1_0CipherList = sort( tlsv1_0CipherList );

    foreach tlsv1_0Cipher( tlsv1_0CipherList ) {
      if( tlsv1_0Cipher =~ "^TLS_.*_3?DES_.*" ) {
        tlsv1_0Vuln = TRUE;
        tlsv1_0tmpReport += tlsv1_0Cipher + ' (SWEET32)\n';
      }
    }

    if( tlsv1_0Vuln ) {
      report += cipherText + ' accepted by this service via the TLSv1.0 protocol:\n\n' + tlsv1_0tmpReport + '\n';
    }
  }
}

if( "TLSv1.1" >< sup_ssl ) {
  tlsv1_1CipherList = get_kb_list( "secpod_ssl_ciphers/tlsv1_1/" + port + "/supported_ciphers" );

  if( ! isnull( tlsv1_1CipherList ) ) {

    # Sort to not report changes on delta reports if just the order is different
    tlsv1_1CipherList = sort( tlsv1_1CipherList );

    foreach tlsv1_1Cipher( tlsv1_1CipherList ) {
      if( tlsv1_1Cipher =~ "^TLS_.*_3?DES_.*" ) {
        tlsv1_1Vuln = TRUE;
        tlsv1_1tmpReport += tlsv1_1Cipher + ' (SWEET32)\n';
      }
    }

    if( tlsv1_1Vuln ) {
      report += cipherText + ' accepted by this service via the TLSv1.1 protocol:\n\n' + tlsv1_1tmpReport + '\n';
    }
  }
}

if( "TLSv1.2" >< sup_ssl ) {
  tlsv1_2CipherList = get_kb_list( "secpod_ssl_ciphers/tlsv1_2/" + port + "/supported_ciphers" );

  if( ! isnull( tlsv1_2CipherList ) ) {

    # Sort to not report changes on delta reports if just the order is different
    tlsv1_2CipherList = sort( tlsv1_2CipherList );

    foreach tlsv1_2Cipher( tlsv1_2CipherList ) {
      if( tlsv1_2Cipher =~ "^TLS_.*_3?DES_.*" ) {
        tlsv1_2Vuln = TRUE;
        tlsv1_2tmpReport += tlsv1_2Cipher + ' (SWEET32)\n';
      }
    }

    if( tlsv1_2Vuln ) {
      report += cipherText + ' accepted by this service via the TLSv1.2 protocol:\n\n' + tlsv1_2tmpReport + '\n';
    }
  }
}

if( report ) {
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
