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
  script_oid("1.3.6.1.4.1.25623.1.0.150713");
  script_version("2021-09-20T08:09:32+0000");
  script_tag(name:"last_modification", value:"2021-09-20 10:59:32 +0000 (Mon, 20 Sep 2021)");
  script_tag(name:"creation_date", value:"2021-09-14 08:36:00 +0000 (Tue, 14 Sep 2021)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N");
  script_tag(name:"severity_origin", value:"Greenbone");
  script_tag(name:"severity_date", value:"2021-09-13 00:00:00 +0000 (Mon, 13 Sep 2020)");

  script_name("Weak Key Exchange (KEX) Algorithm(s) Supported (SSH)");

  script_tag(name:"qod_type", value:"remote_active");
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_tag(name:"solution_type", value:"Mitigation");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_ssh_algos.nasl");
  script_require_ports("Services/ssh", 22);
  script_mandatory_keys("ssh/algos_available");

  script_tag(name:"summary", value:"The remote SSH server is configured to allow / support weak key
  exchange (KEX) algorithm(s).");

  script_tag(name:"vuldetect", value:"Checks the supported KEX algorithms of the remote SSH server.

  Currently weak KEX algorithms are defined as the following:

  - non-elliptic-curve Diffie-Hellmann (DH) KEX algorithms with 1024-bit MODP group / prime

  - ephemerally generated key exchange groups uses SHA-1

  - using RSA 1024-bit modulus key");

  script_tag(name:"insight", value:"- 1024-bit MODP group / prime KEX algorithms:

  Millions of HTTPS, SSH, and VPN servers all use the same prime numbers for Diffie-Hellman key
  exchange. Practitioners believed this was safe as long as new key exchange messages were generated
  for every connection. However, the first step in the number field sieve-the most efficient
  algorithm for breaking a Diffie-Hellman connection-is dependent only on this prime.

  A nation-state can break a 1024-bit prime.");

  script_tag(name:"impact", value:"An attacker can quickly break individual connections.");

  script_tag(name:"solution", value:"Disable the reported weak KEX algorithm(s)

  - 1024-bit MODP group / prime KEX algorithms:

  Alternatively use elliptic-curve Diffie-Hellmann in general, e.g. Curve 25519.");

  script_xref(name:"URL", value:"https://weakdh.org/sysadmin.html");
  script_xref(name:"URL", value:"https://tools.ietf.org/id/draft-ietf-curdle-ssh-kex-sha2-09.html");
  script_xref(name:"URL", value:"https://tools.ietf.org/id/draft-ietf-curdle-ssh-kex-sha2-09.html#rfc.section.5");
  script_xref(name:"URL", value:"https://datatracker.ietf.org/doc/html/rfc6194");

  exit(0);
}

include("ssh_func.inc");
include("list_array_func.inc");
include("port_service_func.inc");
include("misc_func.inc");

# From https://tools.ietf.org/id/draft-ietf-curdle-ssh-kex-sha2-09.html
weak_kex_algos = make_array( "diffie-hellman-group1-sha1", "Using Oakley Group 2 (a 1024-bit MODP group) and SHA-1",
                             "diffie-hellman-group-exchange-sha1", "Using SHA-1",
                             "rsa1024-sha1", "Using RSA 1024-bit modulus key and SHA-1",

                             # nb: Both are listed as gss-gex-sha1-* / gss-group1-sha1-* on draft-ietf-curdle-ssh-kex-sha2-09.html
                             # This is because of the following in https://datatracker.ietf.org/doc/html/rfc4462#section-2.5:
                             # The method name for each method is the concatenation of the string "gss-gex-sha1-" with the Base64 encoding
                             # of the MD5 hash [MD5] of the ASN.1 DER encoding [ASN1] of the underlying GSS-API mechanism's OID.
                             "gss-gex-sha1-", "Using SHA-1",
                             "gss-group1-sha1-", "Using Oakley Group 2 (a 1024-bit MODP group) and SHA-1" );

port = ssh_get_port( default:22 );

if( ! supported_kex_algos = get_kb_list( "ssh/" + port + "/kex_algorithms" ) )
  exit( 0 );

found_weak_kex = FALSE;
weak_kex_algos_report = make_array();

foreach weak_kex_algo( keys( weak_kex_algos ) ) {
  if( in_array( search:weak_kex_algo, array:supported_kex_algos, part_match:TRUE ) ) {
    weak_kex_algos_report[weak_kex_algo] = weak_kex_algos[weak_kex_algo];
    found_weak_kex = TRUE;
  }
}

if( found_weak_kex ) {
  report = '\n\n' + text_format_table( array:weak_kex_algos_report, sep:" | ", columnheader:make_list( "KEX algorithm", "Reason" ) );
  log_message( port:port, data:"The remote SSH server offers the following weak KEX algorithms:" + report );
  exit( 0 );
}

exit( 99 );