###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ssh_weak_encryption_algos.nasl 13581 2019-02-11 14:32:32Z cfischer $
#
# SSH Weak Encryption Algorithms Supported
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105611");
  script_version("$Revision: 13581 $");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"last_modification", value:"$Date: 2019-02-11 15:32:32 +0100 (Mon, 11 Feb 2019) $");
  script_tag(name:"creation_date", value:"2016-04-19 12:49:32 +0200 (Tue, 19 Apr 2016)");
  script_name("SSH Weak Encryption Algorithms Supported");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_ssh_algos.nasl");
  script_require_ports("Services/ssh", 22);
  script_mandatory_keys("ssh/algos_available");

  script_xref(name:"URL", value:"https://tools.ietf.org/html/rfc4253#section-6.3");
  script_xref(name:"URL", value:"https://www.kb.cert.org/vuls/id/958563");

  script_tag(name:"insight", value:"The `arcfour` cipher is the Arcfour stream cipher with 128-bit keys.
  The Arcfour cipher is believed to be compatible with the RC4 cipher [SCHNEIER]. Arcfour (and RC4) has problems
  with weak keys, and should not be used anymore.

  The `none` algorithm specifies that no encryption is to be done.
  Note that this method provides no confidentiality protection, and it
  is NOT RECOMMENDED to use it.

  A vulnerability exists in SSH messages that employ CBC mode that may allow an attacker to recover plaintext from a block of ciphertext.");

  script_tag(name:"vuldetect", value:"Check if remote ssh service supports Arcfour, none or CBC ciphers.");

  script_tag(name:"summary", value:"The remote SSH server is configured to allow weak encryption algorithms.");

  script_tag(name:"solution", value:"Disable the weak encryption algorithms.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_active");

  exit(0);
}

include("ssh_func.inc");

function check_algo( port, type ) {

  local_var encs, port, type;

  if( ! type || ! port )
    return;

  algos = get_kb_list( "ssh/" + port + "/encryption_algorithms_" + type );
  if( ! algos )
    return;

  encs = '';

  # Sort to not report changes on delta reports if just the order is different
  algos = sort( algos );

  foreach found_algo( algos )
    if( "none" >< found_algo || "arcfour" >< found_algo || "-cbc" >< found_algo )
      encs += found_algo + '\n';

  if( strlen( encs ) > 0 )
    return encs;
}

port = get_ssh_port( default:22 );

if( rep = check_algo( port:port, type:"client_to_server" ) )
  report = 'The following weak client-to-server encryption algorithms are supported by the remote service:\n\n' + rep + '\n\n';

if( rep = check_algo( port:port, type:"server_to_client" ) )
  report += 'The following weak server-to-client encryption algorithms are supported by the remote service:\n\n' + rep + '\n\n';

if( report ) {
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );