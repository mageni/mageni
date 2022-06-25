###############################################################################
# OpenVAS Vulnerability Test
# $Id: ssh_proto_version.nasl 13594 2019-02-12 07:55:17Z cfischer $
#
# SSH Protocol Versions Supported
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.100259");
  script_version("$Revision: 13594 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-12 08:55:17 +0100 (Tue, 12 Feb 2019) $");
  script_tag(name:"creation_date", value:"2009-08-25 21:06:41 +0200 (Tue, 25 Aug 2009)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("SSH Protocol Versions Supported");
  script_category(ACT_GATHER_INFO);
  script_family("Service detection");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("gb_ssh_algos.nasl", "ssh_detect.nasl");
  script_require_ports("Services/ssh", 22);
  script_mandatory_keys("ssh/server_banner/available");

  script_tag(name:"summary", value:"Identification of SSH protocol versions supported by the remote
  SSH Server. Also reads the corresponding fingerprints from the service.

  The following versions are tried: 1.33, 1.5, 1.99 and 2.0");

  script_tag(name:"qod_type", value:"remote_active");

  exit(0);
}

include("ssh_func.inc");
include("misc_func.inc");
include("host_details.inc");

vt_strings = get_vt_strings();

function read_key( key, setKB ) {

  local_var key, setKB, key_hex, len, fingerprint, x;

  key_hex = hexstr( MD5( key ) );
  len = strlen( key_hex ); # 32

  for( x = 0; x < len; x += 2 ) {
    fingerprint += substr( key_hex, x, x + 1 );
    if( x + 2 < len ) {
       fingerprint += ":";
     }
  }

  if( setKB ) {
    set_kb_item( name:"SSH/fingerprints/available", value:TRUE );
    if( "ssh-rsa" >< key ) {
      set_kb_item( name:"SSH/" + port + "/fingerprint/ssh-rsa", value:fingerprint );
    } else if( "ssh-dss" >< key ) {
      set_kb_item( name:"SSH/" + port + "/fingerprint/ssh-dss", value:fingerprint );
    }
  }

  return fingerprint;
}

function get_fingerprint( version, port ) {

  local_var version, port;
  local_var buf, header, fingerprint, key, len, soc, algo, rep, key64, sess_id, algos, tmpAlgoList, kb_algos, ka;

  if( version == "2.0" ) {

    algos = make_list();
    tmpAlgoList = make_list();

    kb_algos = get_kb_list( "ssh/" + port + "/server_host_key_algorithms" );
    if( kb_algos ) {
      foreach ka( kb_algos )
        algos = make_list( algos, ka );
    }

    if( ! algos )
      algos = ssh_host_key_algos;

    foreach algo( algos ) {

      soc = open_sock_tcp( port );
      if( ! soc )
        return FALSE;

      ssh_login( socket:soc, keytype:algo );

      sess_id = ssh_session_id_from_sock( soc );
      if( sess_id < 1 ) {
        close( soc );
        continue;
      }

      key = get_server_host_key( sess_id:sess_id );

      close( soc );

      if( algo >!< key )
        continue;

      fingerprint = read_key( key:key );
      key64 = base64( str:key );

      set_kb_item( name:"SSH/fingerprints/available", value:TRUE );
      set_kb_item( name:"SSH/" + port + "/fingerprint/" + algo, value:fingerprint );
      set_kb_item( name:"SSH/" + port + "/publickey/" + algo , value:key64 );

      register_host_detail( name:"ssh-key", value:port + ' ' + algo + ' ' + key64, desc:"SSH Key" );

      tmpAlgoList = make_list( tmpAlgoList, algo + ': ' + fingerprint );
    }

    # Sort to not report changes on delta reports if just the order is different
    tmpAlgoList = sort( tmpAlgoList );

    foreach tmpAlgo( tmpAlgoList )
      rep += '\n' + tmpAlgo;

    return rep;

  } else if( version == "1.5" ) {

    soc = open_sock_tcp( port );
    if( ! soc )
      return FALSE;

    buf = recv_line( socket:soc, length:8192 );
    send( socket:soc, data:'SSH-1.5-' + vt_strings["default"] + '_1.0\n' );

    header = recv( socket:soc, length:4 );
    if( strlen( header ) < 4 )
      return FALSE;

    len = ord( header[2] ) * 256 + ord( header[3] );
    buf = recv( socket:soc, length:len );
    if( ! buf )
      return FALSE;

    buf = header + buf;

    close( soc );

    if( ! key = substr( buf, 132, 259 ) + raw_string( 0x23 ) )
      return FALSE;

    if( fingerprint = read_key( key:key, setKB:TRUE ) ) {
      return fingerprint;
    } else {
      return FALSE;
    }
  } else {
    close( soc );
    return FALSE;
  }
  return fingerprint;
}

# nb: See comment on the purpose of 0.12 below.
versions = make_list( "0.12", "1.33", "1.5", "1.99", "2.0" );

port = get_ssh_port( default:22 );

foreach version( versions ) {

  soc = open_sock_tcp( port );
  if( ! soc )
    exit( 0 );

  ret = recv_line( socket:soc, length:512 );
  if( ! ret ) {
    close( soc );
    exit( 0 );
  }

  if( ! egrep( pattern:"^SSH-.+", string:ret ) ){
    close( soc );
    return( 0 );
  }

  request = string( "SSH-", version, "-", vt_strings["default"], "SSH_1.0\n" );
  send( socket:soc, data:request );

  ret = recv_line( socket:soc, length:500 );
  close( soc );

  # e.g. SSH-1.5-Cisco-1.25 services (and a few more) doesn't answer at all to e.g. version 0.12
  if( ! ret )
    continue;

  if( ! egrep( pattern:"Protocol.*differ", string:ret ) ) {

    # nb: e.g. Dropbear answers to non-existent SSH versions, we assume 2.0 only.
    if( version == "0.12" ) {
      random_ver_response = TRUE;
      version = "2.0";
    }

    supported_versions[version] = version;
    set_kb_item( name:"SSH/supportedversions/" + port, value:version );

    if( random_ver_response )
      break;
  }
}

if( supported_versions ) {

  supported_versions = sort( supported_versions );

  foreach supported( supported_versions ) {
    if( supported == "2.0" || supported == "1.5" ) {
      if( fingerprint = get_fingerprint( version:supported, port:port ) ) {
        if( supported == "2.0" ) {
          fingerprint_info += '\nSSHv2 Fingerprint(s):' + fingerprint;
        } else if( supported == "1.5" ) {
          fingerprint_info += '\nSSHv1 Fingerprint: ' + fingerprint;
        }
      }
    }
    info += string( "\n", chomp( supported ) );
  }

  if( fingerprint_info )
    info += string( "\n", fingerprint_info );

  set_kb_item( name:"SSH/supportedversions/available", value:TRUE );

  if( random_ver_response ) {
    info += '\n\nNote: The remote SSH service is accepting the non-existent SSH Protocol Version 0.12. Because of this behavior it is not possible to fingerprint';
    info += " the exact supported SSH Protocol Version. Based on this support for SSH Protocol Version 2.0 only is assumed.";
  }

  log_message( port:port, data:'The remote SSH Server supports the following SSH Protocol Versions:' + info );
}

exit( 0 );