###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_openssl_export_rsa_freak_attack.nasl 11872 2018-10-12 11:22:41Z cfischer $
#
# SSL/TLS: RSA Temporary Key Handling 'RSA_EXPORT' Downgrade Issue (FREAK)
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
  script_oid("1.3.6.1.4.1.25623.1.0.805142");
  script_version("$Revision: 11872 $");
  script_cve_id("CVE-2015-0204");
  script_bugtraq_id(71936);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:22:41 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-03-06 16:42:13 +0530 (Fri, 06 Mar 2015)");
  script_name("SSL/TLS: RSA Temporary Key Handling 'RSA_EXPORT' Downgrade Issue (FREAK)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("SSL and TLS");
  script_dependencies("secpod_ssl_ciphers.nasl");
  script_mandatory_keys("secpod_ssl_ciphers/supported_ciphers", "ssl_tls/port");

  script_xref(name:"URL", value:"https://freakattack.com");
  script_xref(name:"URL", value:"http://secpod.org/blog/?p=3818");
  script_xref(name:"URL", value:"http://blog.cryptographyengineering.com/2015/03/attack-of-week-freak-or-factoring-nsa.html");

  script_tag(name:"summary", value:"This host is accepting 'RSA_EXPORT' cipher suites
  and is prone to man in the middle attack.");

  script_tag(name:"vuldetect", value:"Check previous collected cipher suites saved in the KB.");

  script_tag(name:"insight", value:"Flaw is due to improper handling RSA
  temporary keys in a non-export RSA key exchange cipher suite.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attacker to downgrade the security of a session to use 'RSA_EXPORT' cipher suites,
  which are significantly weaker than non-export cipher suites. This may allow a
  man-in-the-middle attacker to more easily break the encryption and monitor
  or tamper with the encrypted stream.");

  script_tag(name:"affected", value:"- Hosts accepting 'RSA_EXPORT' cipher suites

  - OpenSSL version before 0.9.8zd, 1.0.0 before 1.0.0p, and 1.0.1 before 1.0.1k.");

  script_tag(name:"solution", value:"- Remove support for 'RSA_EXPORT' cipher
  suites from the service.

  - If running OpenSSL update to version 0.9.8zd or 1.0.0p
  or 1.0.1k or later.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.openssl.org");
  exit(0);
}

include("ssl_funcs.inc");

cipherText = "'RSA_EXPORT' cipher suites";

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
      if( "_RSA_EXPORT_" >< sslv3Cipher ) {
        sslv3Vuln = TRUE;
        sslv3tmpReport += sslv3Cipher + '\n';
      }
    }

    if( sslv3Vuln ) {
      report += cipherText + ' accepted by this service via the SSLv3 protocol:\n\n' + sslv3tmpReport + '\n';
    }
  }
}

if( "TLSv1.0" >< sup_ssl ) {
  tlsv1_0CipherList = get_kb_list( "secpod_ssl_ciphers/tlsv1/" + port + "/supported_ciphers" );

  if( ! isnull( tlsv1_0CipherList ) ) {

    # Sort to not report changes on delta reports if just the order is different
    tlsv1_0CipherList = sort( tlsv1_0CipherList );

    foreach tlsv1_0Cipher( tlsv1_0CipherList ) {
      if( "_RSA_EXPORT_" >< tlsv1_0Cipher ) {
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
      if( "_RSA_EXPORT_" >< tlsv1_1Cipher ) {
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
      if( "_RSA_EXPORT_" >< tlsv1_2Cipher ) {
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
