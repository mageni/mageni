###############################################################################
# OpenVAS Vulnerability Test
# $Id: sw_sslv2_v3_detect.nasl 5547 2017-03-11 12:16:33Z cfi $
#
# SSL/TLS: Deprecated SSLv2 and SSLv3 Protocol Detection
#
# Authors:
# Christian Fischer <info@schutzwerk.com>
#
# Copyright:
# Copyright (c) 2015 SCHUTZWERK GmbH, http://www.schutzwerk.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.111012");
  script_version("$Revision: 5547 $");
  script_cve_id("CVE-2016-0800", "CVE-2014-3566");
  script_tag(name:"last_modification", value:"$Date: 2017-03-11 13:16:33 +0100 (Sat, 11 Mar 2017) $");
  script_tag(name:"creation_date", value:"2015-04-08 07:00:00 +0200 (Wed, 08 Apr 2015)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_name("SSL/TLS: Deprecated SSLv2 and SSLv3 Protocol Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 SCHUTZWERK GmbH");
  script_family("SSL and TLS");
  script_dependencies("gb_tls_version_get.nasl");
  script_mandatory_keys("ssl_tls/port");

  script_tag(name:"summary", value:"It was possible to detect the usage of the
  deprecated SSLv2 and/or SSLv3 protocol on this system.");

  script_tag(name:"vuldetect", value:"Check the used protocols of the services
  provided by this system.");

  script_tag(name:"insight", value:"The SSLv2 and SSLv3 protocols containing
  known cryptographic flaws like:

  - Padding Oracle On Downgraded Legacy Encryption (POODLE, CVE-2014-3566)

  - Decrypting RSA with Obsolete and Weakened eNcryption (DROWN, CVE-2016-0800)");

  script_tag(name:"impact", value:"An attacker might be able to use the known
  cryptographic flaws to eavesdrop the connection between clients and the service
  to get access to sensitive data transferred within the secured connection.");

  script_tag(name:"affected", value:"All services providing an encrypted communication
  using the SSLv2 and/or SSLv3 protocols.");

  script_tag(name:"solution", value:"It is recommended to disable the deprecated
  SSLv2 and/or SSLv3 protocols in favor of the TLSv1+ protocols. Please see the
  references for more information.");

  script_xref(name:"URL", value:"https://www.enisa.europa.eu/activities/identity-and-trust/library/deliverables/algorithms-key-sizes-and-parameters-report");
  script_xref(name:"URL", value:"https://bettercrypto.org/");
  script_xref(name:"URL", value:"https://mozilla.github.io/server-side-tls/ssl-config-generator/");
  script_xref(name:"URL", value:"https://drownattack.com/");
  script_xref(name:"URL", value:"https://www.imperialviolet.org/2014/10/14/poodle.html");

  script_tag(name:"qod_type", value:"remote_app");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include("ssl_funcs.inc");

tlsReport = "In addition to TLSv1.0+ the service is also providing the deprecated";
sslReport = "The service is only providing the deprecated";
cipherReport = "and supports one or more ciphers." +
" Those supported ciphers can be found in the 'SSL/TLS: Report Weak and Supported Ciphers' (OID: 1.3.6.1.4.1.25623.1.0.802067) NVT.";

port = get_ssl_port();
if( ! port ) exit( 0 );
if( ! ssvs = get_kb_item( "tls/supported/" + port ) ) exit( 0 );

if( "SSLv2" >< ssvs ) sslv2 = TRUE;
if( "SSLv3" >< ssvs ) sslv3 = TRUE;
if( "TLSv1.0" >< ssvs ) tlsv10 = TRUE;
if( "TLSv1.1" >< ssvs ) tlsv11 = TRUE;
if( "TLSv1.2" >< ssvs ) tlsv12 = TRUE;

if( ! tlsv10 && ! tlsv11 && ! tlsv12 ) {
  if( sslv2 && sslv3 ) {
    security_message( port:port, data:sslReport + " SSLv2 and SSLv3 protocols " + cipherReport );
    exit( 0 );
  } else if( ! sslv2 && sslv3 ) {
    security_message( port:port, data:sslReport + " SSLv3 protocol " + cipherReport );
    exit( 0 );
  } else if( sslv2 && ! sslv3 ) {
    security_message( port:port, data:sslReport + " SSLv2 protocol " + cipherReport );
    exit( 0 );
  }
} else {
  if( sslv2 && sslv3 ) {
    security_message( port:port, data:tlsReport + " SSLv2 and SSLv3 protocols " + cipherReport );
    exit( 0 );
  } else if( ! sslv2 && sslv3 ) {
    security_message( port:port, data:tlsReport + " SSLv3 protocol " + cipherReport );
    exit( 0 );
  } else if( sslv2 && ! sslv3 ) {
    security_message( port:port, data:tlsReport + " SSLv2 protocol " + cipherReport );
    exit( 0 );
  }
}

exit( 99 );
