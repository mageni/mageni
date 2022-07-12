###############################################################################
# OpenVAS Vulnerability Test
#
# SSL/TLS: Report 'Anonymous' Cipher Suites
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.108147");
  script_version("2019-05-10T14:24:23+0000");
  script_cve_id("CVE-2007-1858", "CVE-2014-0351");
  script_bugtraq_id(28482, 69754);
  script_tag(name:"cvss_base", value:"5.4");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-05-10 14:24:23 +0000 (Fri, 10 May 2019)");
  script_tag(name:"creation_date", value:"2017-04-20 06:08:04 +0200 (Thu, 20 Apr 2017)");
  script_name("SSL/TLS: Report 'Anonymous' Cipher Suites");
  script_category(ACT_GATHER_INFO);
  script_family("SSL and TLS");
  script_copyright("Copyright (c) 2017 Greenbone Networks GmbH");
  script_dependencies("secpod_ssl_ciphers.nasl");
  script_mandatory_keys("secpod_ssl_ciphers/anon_ciphers", "ssl_tls/port");

  script_xref(name:"URL", value:"https://bettercrypto.org/");
  script_xref(name:"URL", value:"https://mozilla.github.io/server-side-tls/ssl-config-generator/");

  script_tag(name:"summary", value:"This routine reports all 'Anonymous' SSL/TLS cipher suites accepted by a service.");

  script_tag(name:"insight", value:"Services supporting 'Anonymous' cipher suites could allow a client to negotiate a
  SSL/TLS connection to the host without any authentication of the remote endpoint.");

  script_tag(name:"impact", value:"This could allow remote attackers to obtain sensitive information
  or have other, unspecified impacts.");

  script_tag(name:"solution", value:"The configuration of this services should be changed so
  that it does not accept the listed 'Anonymous' cipher suites anymore.

  Please see the references for more resources supporting you in this task.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("ssl_funcs.inc");

cipherText = "'Anonymous' cipher suites";

port = get_ssl_port();
if( ! port ) exit( 0 );

# Don't report for StartTLS services. A MitM attacker might be already in the position to
# intercept the initial request for StartTLS and force a fallback to plaintext. This avoids
# also that we're reporting this cipher suites on 'Opportunistic TLS' services like SMTP.
if( get_kb_item( "starttls_typ/" + port ) ) exit( 0 );

sup_ssl = get_kb_item( "tls/supported/" + port );
if( ! sup_ssl ) exit( 0 );

if( "SSLv3" >< sup_ssl ) {
  sslv3CipherList = get_kb_list( "secpod_ssl_ciphers/sslv3/" + port + "/anon_ciphers" );

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
  tlsv1_0CipherList = get_kb_list( "secpod_ssl_ciphers/tlsv1/" + port + "/anon_ciphers" );

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
  tlsv1_1CipherList = get_kb_list( "secpod_ssl_ciphers/tlsv1_1/" + port + "/anon_ciphers" );

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
  tlsv1_2CipherList = get_kb_list( "secpod_ssl_ciphers/tlsv1_2/" + port + "/anon_ciphers" );

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
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
