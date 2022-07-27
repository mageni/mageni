###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_secpod_ssl_ciphers_weak_report.nasl 11135 2018-08-27 13:39:29Z asteins $
#
# SSL/TLS: Report Weak Cipher Suites
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
# Michael Wiegand <michael.wiegand@greenbone.net>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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
  script_oid("1.3.6.1.4.1.25623.1.0.103440");
  script_version("$Revision: 11135 $");
  script_cve_id("CVE-2013-2566", "CVE-2015-2808", "CVE-2015-4000");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-08-27 15:39:29 +0200 (Mon, 27 Aug 2018) $");
  script_tag(name:"creation_date", value:"2012-03-01 17:16:10 +0100 (Thu, 01 Mar 2012)");
  script_name("SSL/TLS: Report Weak Cipher Suites");
  script_category(ACT_GATHER_INFO);
  script_family("SSL and TLS");
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_dependencies("secpod_ssl_ciphers.nasl");
  script_mandatory_keys("secpod_ssl_ciphers/weak_ciphers", "ssl_tls/port");

  script_xref(name:"URL", value:"https://www.bsi.bund.de/SharedDocs/Warnmeldungen/DE/CB/warnmeldung_cb-k16-1465_update_6.html");
  script_xref(name:"URL", value:"https://bettercrypto.org/");
  script_xref(name:"URL", value:"https://mozilla.github.io/server-side-tls/ssl-config-generator/");

  script_tag(name:"summary", value:"This routine reports all Weak SSL/TLS cipher suites accepted by a service.

  NOTE: No severity for SMTP services with 'Opportunistic TLS' and weak cipher suites on port 25/tcp is reported.
  If too strong cipher suites are configured for this service the alternative would be to fall back to an even more insecure
  cleartext communication.");

  script_tag(name:"solution", value:"The configuration of this services should be changed so
  that it does not accept the listed weak cipher suites anymore.

  Please see the references for more resources supporting you with this task.");

  script_tag(name:"insight", value:"These rules are applied for the evaluation of the cryptographic strength:

  - RC4 is considered to be weak (CVE-2013-2566, CVE-2015-2808).

  - Ciphers using 64 bit or less are considered to be vulnerable to brute force methods
  and therefore considered as weak (CVE-2015-4000).

  - 1024 bit RSA authentication is considered to be insecure and therefore as weak.

  - Any cipher considered to be secure for only the next 10 years is considered as medium

  - Any other cipher is considered as strong");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("ssl_funcs.inc");
include("misc_func.inc");

cipherText = "'Weak' cipher suites";

port = get_ssl_port();
if( ! port ) exit( 0 );

sup_ssl = get_kb_item( "tls/supported/" + port );
if( ! sup_ssl ) exit( 0 );

if( "SSLv3" >< sup_ssl ) {
  sslv3CipherList = get_kb_list( "secpod_ssl_ciphers/sslv3/" + port + "/weak_ciphers" );

  if( ! isnull( sslv3CipherList ) ) {

    report += cipherText + ' accepted by this service via the SSLv3 protocol:\n\n';

    # Sort to not report changes on delta reports if just the order is different
    sslv3CipherList = sort( sslv3CipherList );

    foreach sslv3Cipher( sslv3CipherList ) {
      report += sslv3Cipher + '\n';
    }
    report += '\n';
  }
}

if( "TLSv1.0" >< sup_ssl ) {
  tlsv1_0CipherList = get_kb_list( "secpod_ssl_ciphers/tlsv1/" + port + "/weak_ciphers" );

  if( ! isnull( tlsv1_0CipherList ) ) {

    report += cipherText + ' accepted by this service via the TLSv1.0 protocol:\n\n';

    # Sort to not report changes on delta reports if just the order is different
    tlsv1_0CipherList = sort( tlsv1_0CipherList );

    foreach tlsv1_0Cipher( tlsv1_0CipherList ) {
      report += tlsv1_0Cipher + '\n';
    }
    report += '\n';
  }
}

if( "TLSv1.1" >< sup_ssl ) {
  tlsv1_1CipherList = get_kb_list( "secpod_ssl_ciphers/tlsv1_1/" + port + "/weak_ciphers" );

  if( ! isnull( tlsv1_1CipherList ) ) {

    report += cipherText + ' accepted by this service via the TLSv1.1 protocol:\n\n';

    # Sort to not report changes on delta reports if just the order is different
    tlsv1_1CipherList = sort( tlsv1_1CipherList );

    foreach tlsv1_1Cipher( tlsv1_1CipherList ) {
      report += tlsv1_1Cipher + '\n';
    }
    report += '\n';
  }
}

if( "TLSv1.2" >< sup_ssl ) {
  tlsv1_2CipherList = get_kb_list( "secpod_ssl_ciphers/tlsv1_2/" + port + "/weak_ciphers" );

  if( ! isnull( tlsv1_2CipherList ) ) {

    report += cipherText + ' accepted by this service via the TLSv1.2 protocol:\n\n';

    # Sort to not report changes on delta reports if just the order is different
    tlsv1_2CipherList = sort( tlsv1_2CipherList );

    foreach tlsv1_2Cipher( tlsv1_2CipherList ) {
      report += tlsv1_2Cipher + '\n';
    }
    report += '\n';
  }
}

if( report ) {

  if( port == "25" ) {
    if( ports = get_kb_list( "Services/smtp" ) ) {
      if( in_array( search:"25", array:ports ) ) {
        tmpreport = "NOTE: No severity for SMTP services with 'Opportunistic TLS' and weak cipher suites on port 25/tcp is reported. ";
        tmpreport += "If too strong cipher suites are configured for this service the alternative would be to fall back to an even more insecure cleartext communication.";
        log_message( port:port, data:tmpreport + '\n\n' + report );
        exit( 0 );
      }
    }
  }

  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
