# Copyright (C) 2021 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.150749");
  script_version("2021-10-01T09:16:40+0000");
  script_tag(name:"last_modification", value:"2021-10-04 10:20:00 +0000 (Mon, 04 Oct 2021)");
  script_tag(name:"creation_date", value:"2021-09-30 12:44:59 +0000 (Thu, 30 Sep 2021)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N");
  script_tag(name:"severity_origin", value:"Greenbone");
  script_tag(name:"severity_date", value:"2021-09-30 00:00:00 +0000 (Thu, 30 Sep 2021)");

  script_name("SSL/TLS: Server Certificate / Certificate in Chain with ECC keys less than 224 bits");

  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_tag(name:"solution_type", value:"Mitigation");
  script_category(ACT_GATHER_INFO);
  script_family("SSL and TLS");
  script_dependencies("gb_ssl_tls_cert_chain_get.nasl");
  script_mandatory_keys("ssl_tls/port", "ssl_tls/cert_chain/extracted");

  script_tag(name:"summary", value:"The remote SSL/TLS server certificate and/or any of the
  certificates in the certificate chain is using a ECC key with less than 224 bits.");

  script_tag(name:"vuldetect", value:"Checks the ECC keys size of the server certificate and all
  certificates in chain for a size < 224 bit.");

  script_tag(name:"insight", value:"SSL/TLS certificates using ECC keys with less than 224 bits are
  considered unsafe.");

  script_tag(name:"impact", value:"Using certificates with weak ECC key size can lead to
  unauthorized exposure of sensitive information.");

  script_tag(name:"solution", value:"Replace the certificate with a stronger key and reissue the
  certificates it signed.");

  script_xref(name:"URL", value:"https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TR03111/BSI-TR-03111_V-2-0_pdf.pdf");
  script_xref(name:"URL", value:"https://www.keylength.com/en/4/");

  exit(0);
}

include("ssl_funcs.inc");
include("misc_func.inc");

if( ! port = tls_ssl_get_port() )
  exit( 0 );

# nb: Check the server certificate first
if( ! server_cert = get_kb_item( "ssl_tls/cert_chain/" + port + "/certs/server_cert" ) )
  exit( 0 );

# The list of algorithms can be seen here:
# https://gitlab.com/wireshark/wireshark/-/blob/aaad273ec1ead7e2203e66536b0c80fce8c72e49/epan/dissectors/packet-pkcs1.c#L706-733
# nb: The OIDs are included here because the scanner is currently (as of GVM 21.04.2) missing a
# mapping of the OIDs to the plain algorithm names.
check_algorithms  = "^(sec[pt][1-5]|";
check_algorithms += "ecdsa-with-SHA1|1\.2\.840\.10045\.4\.1|";
check_algorithms += "ecdsa-with-SHA224|1\.2\.840\.10045\.4\.3\.1|";
check_algorithms += "ecdsa-with-SHA256|1\.2\.840\.10045\.4\.3\.2|";
check_algorithms += "ecdsa-with-SHA384|1\.2\.840\.10045\.4\.3\.3|";
check_algorithms += "ecdsa-with-SHA512|1\.2\.840\.10045\.4\.3\.4)";

min_key_size = 224;

if( unsafe_cert = tls_ssl_check_small_cert_key_size( cert:server_cert, algorithm_name:check_algorithms, min_key_size:min_key_size ) )
  report = '\n' + unsafe_cert["key-size"] + ":" + unsafe_cert["algorithm"] + ":" + unsafe_cert["serial"] + ":" + unsafe_cert["issuer"] + " (Server certificate)";

chain = get_kb_list( "ssl_tls/cert_chain/" + port + "/certs/chain" );
foreach cert( chain ) {
  if( unsafe_cert = tls_ssl_check_small_cert_key_size( cert:cert, algorithm_name:check_algorithms, min_key_size:min_key_size ) )
    report += '\n' + unsafe_cert["key-size"] + ":" + unsafe_cert["algorithm"] + ":" + unsafe_cert["serial"] + ":" + unsafe_cert["issuer"] + " (Certificate in chain)";
}

if( report ) {
  log_message( port:port, data:'The remote SSL/TLS server is using the following certificate(s) with a ECC key with less than ' + min_key_size + ' bits (key-size:algorithm:serial:issuer):\n' + report );
  exit( 0 );
}

exit( 99 );