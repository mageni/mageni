###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_poodle_sslv3_info_disc_vuln.nasl 11402 2018-09-15 09:13:36Z cfischer $
#
# SSL/TLS: SSLv3 Protocol CBC Cipher Suites Information Disclosure Vulnerability (POODLE)
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802087");
  script_version("$Revision: 11402 $");
  script_cve_id("CVE-2014-3566");
  script_bugtraq_id(70574);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-15 11:13:36 +0200 (Sat, 15 Sep 2018) $");
  script_tag(name:"creation_date", value:"2014-10-16 17:29:43 +0530 (Thu, 16 Oct 2014)");
  script_name("SSL/TLS: SSLv3 Protocol CBC Cipher Suites Information Disclosure Vulnerability (POODLE)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("SSL and TLS");
  script_dependencies("secpod_ssl_ciphers.nasl", "gb_tls_fallback_scsv_enabled.nasl");
  script_mandatory_keys("secpod_ssl_ciphers/supported_ciphers", "ssl_tls/port");

  script_xref(name:"URL", value:"https://www.openssl.org/~bodo/ssl-poodle.pdf");
  script_xref(name:"URL", value:"https://www.imperialviolet.org/2014/10/14/poodle.html");
  script_xref(name:"URL", value:"https://www.dfranke.us/posts/2014-10-14-how-poodle-happened.html");
  script_xref(name:"URL", value:"http://googleonlinesecurity.blogspot.in/2014/10/this-poodle-bites-exploiting-ssl-30.html");

  script_tag(name:"summary", value:"This host is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Evaluate previous collected information about this service.");

  script_tag(name:"insight", value:"The flaw is due to the block cipher padding not being deterministic and not covered by the Message Authentication Code");

  script_tag(name:"impact", value:"Successful exploitation will allow a  man-in-the-middle attackers gain access to the plain text data stream.");

  script_tag(name:"solution", value:"Possible Mitigations are:

  - Disable SSLv3

  - Disable cipher suites supporting CBC cipher modes

  - Enable TLS_FALLBACK_SCSV if the service is providing TLSv1.0+");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include("ssl_funcs.inc");
include("misc_func.inc");

port = get_ssl_port();
if( ! port ) exit( 0 );

if( ! tls_versions = get_kb_item( "tls/supported/" + port ) ) exit( 0 );
if( "SSLv3" >!< tls_versions ) exit( 0 );

# If SSLv3 is supported then check if CBC ciphers are supported and exit if not
cipherList = get_kb_list( "secpod_ssl_ciphers/sslv3/" + port + "/supported_ciphers" );
if( isnull( cipherList ) ) exit( 0 );
if( ! in_array( search:"_CBC_", array:cipherList, part_match:TRUE ) ) exit( 0 );

# If TLSv1.0+ is available check if TLS_FALLBACK_SCSV is supported and mark as vulnerable if not
if( "TLSv" >< tls_versions ) {
  if( ! get_kb_item( "tls_fallback_scsv_supported/" + port ) ) {
    VULN = TRUE;
  }
} else {
  VULN = TRUE;
}

if( VULN ) {
  security_message( port:port );
  exit( 0 );
}

exit( 99 );
