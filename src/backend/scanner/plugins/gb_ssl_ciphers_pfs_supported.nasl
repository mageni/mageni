###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ssl_ciphers_pfs_supported.nasl 4771 2016-12-14 16:02:34Z cfi $
#
# SSL/TLS: Report Perfect Forward Secrecy (PFS) Cipher Suites
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2014 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.105018");
  script_version("$Revision: 4771 $");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"last_modification", value:"$Date: 2016-12-14 17:02:34 +0100 (Wed, 14 Dec 2016) $");
  script_tag(name:"creation_date", value:"2014-05-06 14:16:10 +0100 (Tue, 06 May 2014)");
  script_name("SSL/TLS: Report Perfect Forward Secrecy (PFS) Cipher Suites");
  script_category(ACT_GATHER_INFO);
  script_family("SSL and TLS");
  script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("secpod_ssl_ciphers.nasl");
  script_mandatory_keys("secpod_ssl_ciphers/supported_ciphers", "ssl_tls/port");

  script_tag(name:"summary", value:"This routine reports all SSL/TLS cipher suites accepted by a service which are supporting Perfect Forward Secrecy (PFS).");

  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("ssl_funcs.inc");

cipherText = "Cipher suites supporting Perfect Forward Secrecy (PFS) are accepted by this service via the";

port = get_ssl_port();
if( ! port ) exit( 0 );

sup_ssl = get_kb_item( "tls/supported/" + port );
if( ! sup_ssl ) exit( 0 );

# In theory PFS is supported since SSLv3
if( "SSLv3" >< sup_ssl ) {

  sslv3CipherList = get_kb_list( "secpod_ssl_ciphers/sslv3/" + port + "/supported_ciphers" );

  if( ! isnull( sslv3CipherList ) ) {

    # Sort to not report changes on delta reports if just the order is different
    sslv3CipherList = sort( sslv3CipherList );

    foreach sslv3Cipher( sslv3CipherList ) {
      if( egrep( pattern:'^TLS_(EC)?DHE_', string:sslv3Cipher ) ) {
        sslv3Pfs = TRUE;
        sslv3tmpReport += sslv3Cipher + '\n';
      }
    }

    if( sslv3Pfs ) {
      report += cipherText + ' SSLv3 protocol:\n\n';
      report += sslv3tmpReport;
      report += '\n';
    }
  }
}

if( "TLSv1.0" >< sup_ssl ) {

  tlsv1_0CipherList = get_kb_list( "secpod_ssl_ciphers/tlsv1/" + port + "/supported_ciphers" );

  if( ! isnull( tlsv1_0CipherList ) ) {

    # Sort to not report changes on delta reports if just the order is different
    tlsv1_0CipherList = sort( tlsv1_0CipherList );

    foreach tlsv1_0Cipher( tlsv1_0CipherList ) {
      if( egrep( pattern:'^TLS_(EC)?DHE_', string:tlsv1_0Cipher ) ) {
        tlsv1_0Pfs = TRUE;
        tlsv1_0tmpReport += tlsv1_0Cipher + '\n';
      }
    }

    if( tlsv1_0Pfs ) {
      report += cipherText + ' TLSv1.0 protocol:\n\n';
      report += tlsv1_0tmpReport;
      report += '\n';
    }
  }
}

if( "TLSv1.1" >< sup_ssl ) {

  tlsv1_1CipherList = get_kb_list( "secpod_ssl_ciphers/tlsv1_1/" + port + "/supported_ciphers" );

  if( ! isnull( tlsv1_1CipherList ) ) {

    # Sort to not report changes on delta reports if just the order is different
    tlsv1_1CipherList = sort( tlsv1_1CipherList );

    foreach tlsv1_1Cipher( tlsv1_1CipherList ) {
      if( egrep( pattern:'^TLS_(EC)?DHE_', string:tlsv1_1Cipher ) ) {
        tlsv1_1Pfs = TRUE;
        tlsv1_1tmpReport += tlsv1_1Cipher + '\n';
      }
    }

    if( tlsv1_1Pfs ) {
      report += cipherText + ' TLSv1.1 protocol:\n\n';
      report += tlsv1_1tmpReport;
      report += '\n';
    }
  }
}

if( "TLSv1.2" >< sup_ssl ) {

  tlsv1_2CipherList = get_kb_list( "secpod_ssl_ciphers/tlsv1_2/" + port + "/supported_ciphers" );

  if( ! isnull( tlsv1_2CipherList ) ) {

    # Sort to not report changes on delta reports if just the order is different
    tlsv1_2CipherList = sort( tlsv1_2CipherList );

    foreach tlsv1_2Cipher( tlsv1_2CipherList ) {
      if( egrep( pattern:'^TLS_(EC)?DHE_', string:tlsv1_2Cipher ) ) {
        tlsv1_2Pfs = TRUE;
        tlsv1_2tmpReport += tlsv1_2Cipher + '\n';
      }
    }

    if( tlsv1_2Pfs ) {
      report += cipherText + ' TLSv1.2 protocol:\n\n';
      report += tlsv1_2tmpReport;
      report += '\n';
    }
  }
}

if( report ) {
  log_message( port:port, data:report );
  exit( 0 );
} else {
  set_kb_item( name:"SSL/PFS/no_ciphers", value:TRUE );
  set_kb_item( name:"SSL/PFS/no_ciphers/port", value:port );
  exit( 0 );
}
