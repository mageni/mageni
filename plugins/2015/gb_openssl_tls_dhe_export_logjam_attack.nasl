###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_openssl_tls_dhe_export_logjam_attack.nasl 11872 2018-10-12 11:22:41Z cfischer $
#
# SSL/TLS: 'DHE_EXPORT' Man in the Middle Security Bypass Vulnerability (LogJam)
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.805188");
  script_version("$Revision: 11872 $");
  script_cve_id("CVE-2015-4000");
  script_bugtraq_id(74733);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:22:41 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-05-22 13:17:23 +0530 (Fri, 22 May 2015)");
  script_name("SSL/TLS: 'DHE_EXPORT' Man in the Middle Security Bypass Vulnerability (LogJam)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("SSL and TLS");
  script_dependencies("secpod_ssl_ciphers.nasl");
  script_mandatory_keys("secpod_ssl_ciphers/supported_ciphers", "ssl_tls/port");

  script_xref(name:"URL", value:"https://weakdh.org");
  script_xref(name:"URL", value:"https://weakdh.org/imperfect-forward-secrecy.pdf");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2015/05/20/8");
  script_xref(name:"URL", value:"https://blog.cloudflare.com/logjam-the-latest-tls-vulnerability-explained");
  script_xref(name:"URL", value:"https://www.openssl.org/blog/blog/2015/05/20/logjam-freak-upcoming-changes");

  script_tag(name:"summary", value:"This host is accepting 'DHE_EXPORT' cipher suites
  and is prone to man in the middle attack.");

  script_tag(name:"vuldetect", value:"Check previous collected cipher suites saved in the KB.");

  script_tag(name:"insight", value:"Flaw is triggered when handling
  Diffie-Hellman key exchanges defined in the 'DHE_EXPORT' cipher suites.");

  script_tag(name:"impact", value:"Successful exploitation will allow a
  man-in-the-middle attacker to downgrade the security of a TLS session to
  512-bit export-grade cryptography, which is significantly weaker, allowing
  the attacker to more easily break the encryption and monitor or tamper with
  the encrypted stream.");

  script_tag(name:"affected", value:"- Hosts accepting 'DHE_EXPORT' cipher suites

  - OpenSSL version before 1.0.2b and 1.0.1n");

  script_tag(name:"solution", value:"- Remove support for 'DHE_EXPORT' cipher
  suites from the service

  - If running OpenSSL updateto version 1.0.2b or 1.0.1n or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("ssl_funcs.inc");

cipherText = "'DHE_EXPORT' cipher suites";

port = get_ssl_port();
if( ! port ) exit( 0 );

sup_ssl = get_kb_item( "tls/supported/" + port );
if( ! sup_ssl ) exit( 0 );

if( "SSLv3" >< sup_ssl ) {
  sslv3CipherList = get_kb_list( "secpod_ssl_ciphers/sslv3/" + port + "/supported_ciphers" );

  if( ! isnull( sslv3CipherList ) ) {

    # Sort to not report changes on delta reports if just the order is different
    sslv3CipherList = sort( sslv3CipherList );

    foreach sslv3Cipher( sslv3CipherList ) {
      if( sslv3Cipher =~ "^TLS_DHE?_.*_EXPORT_" ) {
        sslv3Vuln = TRUE;
        sslv3tmpReport += sslv3Cipher + '\n';
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
      if( tlsv1_0Cipher =~ "^TLS_DHE?_.*_EXPORT_" ) {
        tlsv1_0Vuln = TRUE;
        tlsv1_0tmpReport += tlsv1_0Cipher + '\n';
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
      if( tlsv1_1Cipher =~ "^TLS_DHE?_.*_EXPORT_" ) {
        tlsv1_1Vuln = TRUE;
        tlsv1_1tmpReport += tlsv1_1Cipher + '\n';
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
      if( tlsv1_2Cipher =~ "^TLS_DHE?_.*_EXPORT_" ) {
        tlsv1_2Vuln = TRUE;
        tlsv1_2tmpReport += tlsv1_2Cipher + '\n';
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
