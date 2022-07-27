###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ssl_ciphers_report.nasl 11108 2018-08-24 14:27:07Z mmartin $
#
# SSL/TLS: Report Supported Cipher Suites
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.802067");
  script_version("$Revision: 11108 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-08-24 16:27:07 +0200 (Fri, 24 Aug 2018) $");
  script_tag(name:"creation_date", value:"2014-03-06 17:20:28 +0530 (Thu, 06 Mar 2014)");
  script_name("SSL/TLS: Report Supported Cipher Suites");
  script_category(ACT_GATHER_INFO);
  script_family("SSL and TLS");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("secpod_ssl_ciphers.nasl");
  script_mandatory_keys("secpod_ssl_ciphers/supported_ciphers", "secpod_ssl_ciphers/started", "ssl_tls/port");
  script_add_preference(name:"Report timeout", type:"checkbox", value:"no");

  script_tag(name:"summary", value:"This routine reports all SSL/TLS cipher suites accepted by a service.

  As the NVT 'SSL/TLS: Check Supported Cipher Suites' (OID: 1.3.6.1.4.1.25623.1.0.900234) might run into a
  timeout the actual reporting of all accepted cipher suites takes place in this NVT instead. The script preference 'Report timeout'
  allows you to configure if such an timeout is reported.");

  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("ssl_funcs.inc");

strongCipherText = "'Strong' cipher suites";
mediumCipherText = "'Medium' cipher suites";
weakCipherText = "'Weak' cipher suites";
nullCipherText = "'Null' cipher suites";
anonCipherText = "'Anonymous' cipher suites";

port = get_ssl_port();
if( ! port ) exit( 0 );

reportTimeout = script_get_preference( "Report timeout" );

if( reportTimeout == 'yes' ) {
  if( ! get_kb_item( "secpod_ssl_ciphers/" + port + "/no_timeout" ) ) {
    timeoutReport = "A timeout happened during the check for SSL/TLS weak and supported ciphers. " +
                    "Consider raising the script_timeout value of the NVT " +
                    "'SSL/TLS: Check Supported Cipher Suites' " +
                    "(OID: 1.3.6.1.4.1.25623.1.0.900234).";
    log_message( port:port, data:timeoutReport);
  }
}

sup_ssl = get_kb_item( "tls/supported/" + port );
if( ! sup_ssl ) exit( 0 );

if( "SSLv3" >< sup_ssl ) {

  sslv3StrongCipherList = get_kb_list( "secpod_ssl_ciphers/sslv3/" + port + "/strong_ciphers" );
  sslv3MediumCipherList = get_kb_list( "secpod_ssl_ciphers/sslv3/" + port + "/medium_ciphers" );
  sslv3WeakCipherList = get_kb_list( "secpod_ssl_ciphers/sslv3/" + port + "/weak_ciphers" );
  sslv3NullCipherList = get_kb_list( "secpod_ssl_ciphers/sslv3/" + port + "/null_ciphers" );
  sslv3AnonCipherList = get_kb_list( "secpod_ssl_ciphers/sslv3/" + port + "/anon_ciphers" );

  if( ! isnull( sslv3StrongCipherList ) ) {

    report += strongCipherText + ' accepted by this service via the SSLv3 protocol:\n\n';

    # Sort to not report changes on delta reports if just the order is different
    sslv3StrongCipherList = sort( sslv3StrongCipherList );

    foreach sslv3StrongCipher( sslv3StrongCipherList ) {
      report += sslv3StrongCipher + '\n';
    }
    report += '\n';
  } else {
    report += 'No ' + strongCipherText + ' accepted by this service via the SSLv3 protocol.\n\n';
  }

  if( ! isnull( sslv3MediumCipherList ) ) {

    report += mediumCipherText + ' accepted by this service via the SSLv3 protocol:\n\n';

    # Sort to not report changes on delta reports if just the order is different
    sslv3MediumCipherList = sort( sslv3MediumCipherList );

    foreach sslv3MediumCipher( sslv3MediumCipherList ) {
      report += sslv3MediumCipher + '\n';
    }
    report += '\n';
  } else {
    report += 'No ' + mediumCipherText + ' accepted by this service via the SSLv3 protocol.\n\n';
  }

  if( ! isnull( sslv3WeakCipherList ) ) {

    report += weakCipherText + ' accepted by this service via the SSLv3 protocol:\n\n';

    # Sort to not report changes on delta reports if just the order is different
    sslv3WeakCipherList = sort( sslv3WeakCipherList );

    foreach sslv3WeakCipher( sslv3WeakCipherList ) {
      report += sslv3WeakCipher + '\n';
    }
    report += '\n';
  } else {
    report += 'No ' + weakCipherText + ' accepted by this service via the SSLv3 protocol.\n\n';
  }

  if( ! isnull( sslv3NullCipherList ) ) {

    report += nullCipherText + ' accepted by this service via the SSLv3 protocol:\n\n';

    # Sort to not report changes on delta reports if just the order is different
    sslv3NullCipherList = sort( sslv3NullCipherList );

    foreach sslv3NullCipher( sslv3NullCipherList ) {
      report += sslv3NullCipher + '\n';
    }
    report += '\n';
  } else {
    report += 'No ' + nullCipherText + ' accepted by this service via the SSLv3 protocol.\n\n';
  }

  if( ! isnull( sslv3AnonCipherList ) ) {

    report += anonCipherText + ' accepted by this service via the SSLv3 protocol:\n\n';

    # Sort to not report changes on delta reports if just the order is different
    sslv3AnonCipherList = sort( sslv3AnonCipherList );

    foreach sslv3AnonCipher( sslv3AnonCipherList ) {
      report += sslv3AnonCipher + '\n';
    }
    report += '\n';
  } else {
    report += 'No ' + anonCipherText + ' accepted by this service via the SSLv3 protocol.\n\n';
  }
}

if( "TLSv1.0" >< sup_ssl ) {

  tlsv1_0StrongCipherList = get_kb_list( "secpod_ssl_ciphers/tlsv1/" + port + "/strong_ciphers" );
  tlsv1_0MediumCipherList = get_kb_list( "secpod_ssl_ciphers/tlsv1/" + port + "/medium_ciphers" );
  tlsv1_0WeakCipherList = get_kb_list( "secpod_ssl_ciphers/tlsv1/" + port + "/weak_ciphers" );
  tlsv1_0NullCipherList = get_kb_list( "secpod_ssl_ciphers/tlsv1/" + port + "/null_ciphers" );
  tlsv1_0AnonCipherList = get_kb_list( "secpod_ssl_ciphers/tlsv1/" + port + "/anon_ciphers" );

  if( ! isnull( tlsv1_0StrongCipherList ) ) {

    report += strongCipherText + ' accepted by this service via the TLSv1.0 protocol:\n\n';

    # Sort to not report changes on delta reports if just the order is different
    tlsv1_0StrongCipherList = sort( tlsv1_0StrongCipherList );

    foreach tlsv1_0StrongCipher( tlsv1_0StrongCipherList ) {
      report += tlsv1_0StrongCipher + '\n';
    }
    report += '\n';
  } else {
    report += 'No ' + strongCipherText + ' accepted by this service via the TLSv1.0 protocol.\n\n';
  }

  if( ! isnull( tlsv1_0MediumCipherList ) ) {

    report += mediumCipherText + ' accepted by this service via the TLSv1.0 protocol:\n\n';

    # Sort to not report changes on delta reports if just the order is different
    tlsv1_0MediumCipherList = sort( tlsv1_0MediumCipherList );

    foreach tlsv1_0MediumCipher( tlsv1_0MediumCipherList ) {
      report += tlsv1_0MediumCipher + '\n';
    }
    report += '\n';
  } else {
    report += 'No ' + mediumCipherText + ' accepted by this service via the TLSv1.0 protocol.\n\n';
  }

  if( ! isnull( tlsv1_0WeakCipherList ) ) {

    report += weakCipherText + ' accepted by this service via the TLSv1.0 protocol:\n\n';

    # Sort to not report changes on delta reports if just the order is different
    tlsv1_0WeakCipherList = sort( tlsv1_0WeakCipherList );

    foreach tlsv1_0WeakCipher( tlsv1_0WeakCipherList ) {
      report += tlsv1_0WeakCipher + '\n';
    }
    report += '\n';
  } else {
    report += 'No ' + weakCipherText + ' accepted by this service via the TLSv1.0 protocol.\n\n';
  }

  if( ! isnull( tlsv1_0NullCipherList ) ) {

    report += nullCipherText + ' accepted by this service via the TLSv1.0 protocol:\n\n';

    # Sort to not report changes on delta reports if just the order is different
    tlsv1_0NullCipherList = sort( tlsv1_0NullCipherList );

    foreach tlsv1_0NullCipher( tlsv1_0NullCipherList ) {
      report += tlsv1_0NullCipher + '\n';
    }
    report += '\n';
  } else {
    report += 'No ' + nullCipherText + ' accepted by this service via the TLSv1.0 protocol.\n\n';
  }

  if( ! isnull( tlsv1_0AnonCipherList ) ) {

    report += anonCipherText + ' accepted by this service via the TLSv1.0 protocol:\n\n';

    # Sort to not report changes on delta reports if just the order is different
    tlsv1_0AnonCipherList = sort( tlsv1_0AnonCipherList );

    foreach tlsv1_0AnonCipher( tlsv1_0AnonCipherList ) {
      report += tlsv1_0AnonCipher + '\n';
    }
    report += '\n';
  } else {
    report += 'No ' + anonCipherText + ' accepted by this service via the TLSv1.0 protocol.\n\n';
  }
}

if( "TLSv1.1" >< sup_ssl ) {

  tlsv1_1StrongCipherList = get_kb_list( "secpod_ssl_ciphers/tlsv1_1/" + port + "/strong_ciphers" );
  tlsv1_1MediumCipherList = get_kb_list( "secpod_ssl_ciphers/tlsv1_1/" + port + "/medium_ciphers" );
  tlsv1_1WeakCipherList = get_kb_list( "secpod_ssl_ciphers/tlsv1_1/" + port + "/weak_ciphers" );
  tlsv1_1NullCipherList = get_kb_list( "secpod_ssl_ciphers/tlsv1_1/" + port + "/null_ciphers" );
  tlsv1_1AnonCipherList = get_kb_list( "secpod_ssl_ciphers/tlsv1_1/" + port + "/anon_ciphers" );

  if( ! isnull( tlsv1_1StrongCipherList ) ) {

    report += strongCipherText + ' accepted by this service via the TLSv1.1 protocol:\n\n';

    # Sort to not report changes on delta reports if just the order is different
    tlsv1_1StrongCipherList = sort( tlsv1_1StrongCipherList );

    foreach tlsv1_1StrongCipher( tlsv1_1StrongCipherList ) {
      report += tlsv1_1StrongCipher + '\n';
    }
    report += '\n';
  } else {
    report += 'No ' + strongCipherText + ' accepted by this service via the TLSv1.1 protocol.\n\n';
  }

  if( ! isnull( tlsv1_1MediumCipherList ) ) {

    report += mediumCipherText + ' accepted by this service via the TLSv1.1 protocol:\n\n';

    # Sort to not report changes on delta reports if just the order is different
    tlsv1_1MediumCipherList = sort( tlsv1_1MediumCipherList );

    foreach tlsv1_1MediumCipher( tlsv1_1MediumCipherList ) {
      report += tlsv1_1MediumCipher + '\n';
    }
    report += '\n';
  } else {
    report += 'No ' + mediumCipherText + ' accepted by this service via the TLSv1.1 protocol.\n\n';
  }

  if( ! isnull( tlsv1_1WeakCipherList ) ) {

    report += weakCipherText + ' accepted by this service via the TLSv1.1 protocol:\n\n';

    # Sort to not report changes on delta reports if just the order is different
    tlsv1_1WeakCipherList = sort( tlsv1_1WeakCipherList );

    foreach tlsv1_1WeakCipher( tlsv1_1WeakCipherList ) {
      report += tlsv1_1WeakCipher + '\n';
    }
    report += '\n';
  } else {
    report += 'No ' + weakCipherText + ' accepted by this service via the TLSv1.1 protocol.\n\n';
  }

  if( ! isnull( tlsv1_1NullCipherList ) ) {

    report += nullCipherText + ' accepted by this service via the TLSv1.1 protocol:\n\n';

    # Sort to not report changes on delta reports if just the order is different
    tlsv1_1NullCipherList = sort( tlsv1_1NullCipherList );

    foreach tlsv1_1NullCipher( tlsv1_1NullCipherList ) {
      report += tlsv1_1NullCipher + '\n';
    }
    report += '\n';
  } else {
    report += 'No ' + nullCipherText + ' accepted by this service via the TLSv1.1 protocol.\n\n';
  }

  if( ! isnull( tlsv1_1AnonCipherList ) ) {

    report += anonCipherText + ' accepted by this service via the TLSv1.1 protocol:\n\n';

    # Sort to not report changes on delta reports if just the order is different
    tlsv1_1AnonCipherList = sort( tlsv1_1AnonCipherList );

    foreach tlsv1_1AnonCipher( tlsv1_1AnonCipherList ) {
      report += tlsv1_1AnonCipher + '\n';
    }
    report += '\n';
  } else {
    report += 'No ' + anonCipherText + ' accepted by this service via the TLSv1.1 protocol.\n\n';
  }
}

if( "TLSv1.2" >< sup_ssl ) {

  tlsv1_2StrongCipherList = get_kb_list( "secpod_ssl_ciphers/tlsv1_2/" + port + "/strong_ciphers" );
  tlsv1_2MediumCipherList = get_kb_list( "secpod_ssl_ciphers/tlsv1_2/" + port + "/medium_ciphers" );
  tlsv1_2WeakCipherList = get_kb_list( "secpod_ssl_ciphers/tlsv1_2/" + port + "/weak_ciphers" );
  tlsv1_2NullCipherList = get_kb_list( "secpod_ssl_ciphers/tlsv1_2/" + port + "/null_ciphers" );
  tlsv1_2AnonCipherList = get_kb_list( "secpod_ssl_ciphers/tlsv1_2/" + port + "/anon_ciphers" );

  if( ! isnull( tlsv1_2StrongCipherList ) ) {

    report += strongCipherText + ' accepted by this service via the TLSv1.2 protocol:\n\n';

    # Sort to not report changes on delta reports if just the order is different
    tlsv1_2StrongCipherList = sort( tlsv1_2StrongCipherList );

    foreach tlsv1_2StrongCipher( tlsv1_2StrongCipherList ) {
      report += tlsv1_2StrongCipher + '\n';
    }
    report += '\n';
  } else {
    report += 'No ' + strongCipherText + ' accepted by this service via the TLSv1.2 protocol.\n\n';
  }

  if( ! isnull( tlsv1_2MediumCipherList ) ) {

    report += mediumCipherText + ' accepted by this service via the TLSv1.2 protocol:\n\n';

    # Sort to not report changes on delta reports if just the order is different
    tlsv1_2MediumCipherList = sort( tlsv1_2MediumCipherList );

    foreach tlsv1_2MediumCipher( tlsv1_2MediumCipherList ) {
      report += tlsv1_2MediumCipher + '\n';
    }
    report += '\n';
  } else {
    report += 'No ' + mediumCipherText + ' accepted by this service via the TLSv1.2 protocol.\n\n';
  }

  if( ! isnull( tlsv1_2WeakCipherList ) ) {

    report += weakCipherText + ' accepted by this service via the TLSv1.2 protocol:\n\n';

    # Sort to not report changes on delta reports if just the order is different
    tlsv1_2WeakCipherList = sort( tlsv1_2WeakCipherList );

    foreach tlsv1_2WeakCipher( tlsv1_2WeakCipherList ) {
      report += tlsv1_2WeakCipher + '\n';
    }
    report += '\n';
  } else {
    report += 'No ' + weakCipherText + ' accepted by this service via the TLSv1.2 protocol.\n\n';
  }

  if( ! isnull( tlsv1_2NullCipherList ) ) {

    report += nullCipherText + ' accepted by this service via the TLSv1.2 protocol:\n\n';

    # Sort to not report changes on delta reports if just the order is different
    tlsv1_2NullCipherList = sort( tlsv1_2NullCipherList );

    foreach tlsv1_2NullCipher( tlsv1_2NullCipherList ) {
      report += tlsv1_2NullCipher + '\n';
    }
    report += '\n';
  } else {
    report += 'No ' + nullCipherText + ' accepted by this service via the TLSv1.2 protocol.\n\n';
  }

  if( ! isnull( tlsv1_2AnonCipherList ) ) {

    report += anonCipherText + ' accepted by this service via the TLSv1.2 protocol:\n\n';

    # Sort to not report changes on delta reports if just the order is different
    tlsv1_2AnonCipherList = sort( tlsv1_2AnonCipherList );

    foreach tlsv1_2AnonCipher( tlsv1_2AnonCipherList ) {
      report += tlsv1_2AnonCipher + '\n';
    }
    report += '\n';
  } else {
    report += 'No ' + anonCipherText + ' accepted by this service via the TLSv1.2 protocol.\n\n';
  }
}

if( report ) {
  log_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
