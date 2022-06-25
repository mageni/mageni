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
  script_oid("1.3.6.1.4.1.25623.1.0.150712");
  script_version("2021-09-20T08:09:32+0000");
  script_tag(name:"last_modification", value:"2021-09-20 10:59:32 +0000 (Mon, 20 Sep 2021)");
  script_tag(name:"creation_date", value:"2021-09-13 09:44:40 +0000 (Mon, 13 Sep 2021)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N");
  script_tag(name:"severity_origin", value:"Greenbone");
  script_tag(name:"severity_date", value:"2021-09-13 00:00:00 +0000 (Mon, 13 Sep 2020)");

  script_name("Weak (Small) Public Key Size(s) (SSH)");

  script_tag(name:"qod_type", value:"remote_active");
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_tag(name:"solution_type", value:"Mitigation");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("ssh_proto_version.nasl");
  script_require_ports("Services/ssh", 22);
  script_mandatory_keys("SSH/fingerprints/available");

  script_tag(name:"summary", value:"The remote SSH server uses a weak (too small) public key
  size.");

  script_tag(name:"vuldetect", value:"Checks the public key size of the remote SSH server.

  Currently weak (too small) key sizes are defined as the following:

  - <= 1024 bit for RSA based keys");

  script_tag(name:"insight", value:"- <= 1024 bit for RSA based keys:

  Best practices require that RSA digital signatures be 2048 or more bits long to provide adequate
  security. Key lengths of 1024 are considered deprecated since 2011.");

  script_tag(name:"impact", value:"A man-in-the-middle attacker can exploit this vulnerability to
  record the communication to decrypt the session key and even the messages.");

  script_tag(name:"solution", value:"- <= 1024 bit for RSA based keys:

  Install a RSA public key length of 2048 bits or greater, or to switch to more secure key types.");

  script_xref(name:"URL", value:"https://www.linuxminion.com/ssh-server-public-key-too-small/");

  exit(0);
}

include("ssh_func.inc");
include("misc_func.inc");
include("http_func.inc");
include("port_service_func.inc");

port = ssh_get_port( default:22 );

if( ! key = get_kb_item( "SSH/" + port + "/publickey/ssh-rsa" ) )
  exit( 0 );

# Props to https://security.stackexchange.com/questions/42268/how-do-i-get-the-rsa-bit-length-with-the-pubkey-and-openssl
rsa_key = base64_decode( str:key );
hex_rsa_key = hexstr( rsa_key );

counter = 0;

# First 4 bytes: length of next bytes describing the key type
# RSA: 00000007 (hex) -> 7 bytes
for( x = 0; x < 8; x++ ) {
  hex_length_of_key_type += hex_rsa_key[counter];
  counter++;
}
length_of_key_type = hex2dec( xvalue:hex_length_of_key_type );

# Name of keytype
# RSA: 7373682d727361 (hex) -> ssh-rsa
for( x = 0; x < int( length_of_key_type ) * 2; x++ ) {
  hex_type_of_key += hex_rsa_key[counter];
  counter++;
}
type_of_key = hex2str( hex_type_of_key );

# Length of public exponent
# RSA: 00000003 (hex) -> 3 bytes
for( x = 0; x < 8; x++ ) {
  hex_length_of_public_exponent += hex_rsa_key[counter];
  counter++;
}
length_of_public_exponent = hex2dec( xvalue:hex_length_of_public_exponent );

# Public exponent
# RSA: 010001 (hex) -> 65537
for( x = 0; x < int( length_of_public_exponent ) * 2; x++ ) {
  hex_public_exponent += hex_rsa_key[counter];
  counter++;
}
public_exponent = hex2dec( xvalue:hex_public_exponent );

# modulus length, aka bitsize of the key
# RSA: 00000101 -> 257
# First byte is "00" (that first byte was added so that the value is considered positive, because
# the internal encoding rules call for signed integers, the first bit defining the sign).
# -> 256bytes == 2048bits
for( x = 0; x < 8; x++ ) {
  hex_modulus_bytes += hex_rsa_key[counter];
  counter++;
}
modulus_bytes = hex2dec( xvalue:hex_modulus_bytes );
modulus_bits = ( hex2dec( xvalue:hex_modulus_bytes ) -1 ) * 8;

if( int( modulus_bits ) <= 1024 ) {
  log_message( port:port, data:"The remote SSH server uses a public RSA key with the following weak (too small) size: " + modulus_bits );
  exit( 0 );
}

exit( 99 );