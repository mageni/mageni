###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_secpod_ssl_ciphers_noweak_report.nasl 4736 2016-12-10 11:17:19Z cfi $
#
# SSL/TLS: Report Non Weak Cipher Suites
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
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
  script_oid("1.3.6.1.4.1.25623.1.0.103441");
  script_version("$Revision: 4736 $");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"last_modification", value:"$Date: 2016-12-10 12:17:19 +0100 (Sat, 10 Dec 2016) $");
  script_tag(name:"creation_date", value:"2012-03-01 17:16:10 +0100 (Thu, 01 Mar 2012)");
  script_name("SSL/TLS: Report Non Weak Cipher Suites");
  script_category(ACT_GATHER_INFO);
  script_family("SSL and TLS");
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_dependencies("secpod_ssl_ciphers.nasl");
  script_mandatory_keys("secpod_ssl_ciphers/nonweak_ciphers", "ssl_tls/port");

  script_tag(name:"summary", value:"This routine reports all Non Weak SSL/TLS cipher suites accepted by a service.");

  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("ssl_funcs.inc");

cipherText = "'Non Weak' cipher suites";

port = get_ssl_port();
if( ! port ) exit( 0 );

sup_ssl = get_kb_item( "tls/supported/" + port );
if( ! sup_ssl ) exit( 0 );

# All SSLv2 ciphers are considered as weak so we don't report them here
if( "SSLv3" >< sup_ssl ) {
  sslv3CipherList = get_kb_list( "secpod_ssl_ciphers/sslv3/" + port + "/nonweak_ciphers" );

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
  tlsv1_0CipherList = get_kb_list( "secpod_ssl_ciphers/tlsv1/" + port + "/nonweak_ciphers" );

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
  tlsv1_1CipherList = get_kb_list( "secpod_ssl_ciphers/tlsv1_1/" + port + "/nonweak_ciphers" );

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
  tlsv1_2CipherList = get_kb_list( "secpod_ssl_ciphers/tlsv1_2/" + port + "/nonweak_ciphers" );

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
  log_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
