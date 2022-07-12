###############################################################################
# OpenVAS Vulnerability Test
#
# SSH Login Failed For Authenticated Checks
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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
  script_oid("1.3.6.1.4.1.25623.1.0.105936");
  script_version("2019-05-08T08:20:56+0000");
  script_tag(name:"last_modification", value:"2019-05-08 08:20:56 +0000 (Wed, 08 May 2019)");
  script_tag(name:"creation_date", value:"2014-12-16 10:58:24 +0700 (Tue, 16 Dec 2014)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("SSH Login Failed For Authenticated Checks");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("ssh_authorization.nasl", "gb_ssh_algos.nasl");
  script_mandatory_keys("login/SSH/failed");

  script_xref(name:"URL", value:"https://documentation.mageni.net");

  script_tag(name:"summary", value:"It was NOT possible to login using the provided SSH
  credentials. Hence authenticated checks are NOT enabled.");

  script_tag(name:"solution", value:"Recheck the SSH credentials for authenticated checks or
  evaluate the script output for the required algorithms on the remote SSH server or the scanner.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("misc_func.inc");
include("ssh_func.inc");

libssh_supported = make_array();
host_supported   = make_array();
host_unsupported = make_array();

# The types we want to check defined in gb_ssh_algos.ssh
check_types = make_list(
"kex_algorithms",
"server_host_key_algorithms",
"encryption_algorithms_server_to_client",
"mac_algorithms_server_to_client",
"compression_algorithms_server_to_client" );

# The list of features libssh is currently supporting.
# See https://www.libssh.org/features/
libssh_supported['kex_algorithms'] = make_list(
"curve25519-sha256", # New alias for the one below, available in libssh >= 0.8.0 but requires libssh build against libnacl
"curve25519-sha256@libssh.org", # Available in libssh >= 0.6.0 but requires libssh build against libnacl
"ecdh-sha2-nistp256",
"diffie-hellman-group1-sha1",
"diffie-hellman-group14-sha1" );

libssh_supported['server_host_key_algorithms'] = make_list(
"ssh-ed25519", # Available in libssh >= 0.7.0
"ecdsa-sha2-nistp256",
"ecdsa-sha2-nistp384",
"ecdsa-sha2-nistp521",
"ssh-rsa",
# nb: Both seems to be only available as a patch: https://www.libssh.org/archive/libssh/2018-06/0000047.html
# but not available yet in libssh up to 0.8.2 even if those are listed at the features page.
# "rsa-sha2-512",
# "rsa-sha2-256",
"ssh-dss"
);

libssh_supported['encryption_algorithms_server_to_client'] = make_list(
"chachae20-poly1305", # Available in libssh >= 0.8.0
"aes256-ctr",
"aes192-ctr",
"aes128-ctr",
"aes256-cbc",
"aes192-cbc",
"aes128-cbc",
"3des-cbc",
"blowfish-cbc"
);

libssh_supported['mac_algorithms_server_to_client'] = make_list(
"hmac-sha2-512", # Available in libssh >= 0.7.0
"hmac-sha2-256", # Available in libssh >= 0.7.0
"hmac-sha1",
"none"
);

libssh_supported['compression_algorithms_server_to_client'] = make_list(
"zlib@openssh.com",
"zlib",
"none"
);

port = kb_ssh_transport();

if( get_kb_item( "ssh/" + port + "/algos_available" ) ) {

  foreach check_type( check_types ) {

    host_list = get_kb_list( "ssh/" + port + "/" + check_type );

    if( host_list ) {

      host_unsupported[check_type] = make_list();
      host_supported[check_type]   = make_list( host_list );

      foreach single_item( host_list ) {
        if( ! in_array( search:single_item, array:libssh_supported[check_type] ) ) {
          host_unsupported[check_type] = make_list( host_unsupported[check_type], single_item );
        }
      }
    }
  }
}

foreach check_type( check_types ) {

  host_supported_items   = max_index( host_supported[check_type] );
  host_unsupported_items = max_index( host_unsupported[check_type] );

  if( host_supported_items <= host_unsupported_items && host_unsupported_items > 0 ) {
    unsupported_report += 'Current supported ' + check_type + ' of the scanner:\n\n';
    unsupported_report += join( list:sort( libssh_supported[check_type] ), sep:'\n' ) + '\n\n';
    unsupported_report += 'Current supported ' + check_type + ' of the remote host:\n\n';
    unsupported_report += join( list:sort( host_supported[check_type] ), sep:'\n' ) + '\n\n';
  }

  # Those depends on the libssh version and partly if the libssh is built against libnacl or not.
  if( check_type == "kex_algorithms" && host_supported_items > 0 &&
      ( in_array( search:"curve25519-sha256@libssh.org", array:libssh_supported[check_type] ) ||
        in_array( search:"curve25519-sha256", array:libssh_supported[check_type] ) ) ) {
    version_dep_report += 'Current supported ' + check_type + ' of the scanner:\n\n';
    version_dep_report += join( list:sort( libssh_supported[check_type] ), sep:'\n' ) + '\n\n';
    version_dep_report = ereg_replace( string:version_dep_report, pattern:"curve25519-sha256(@libssh\.org)?", replace:"\0 (requires libssh >= 0.6.0 on the scanner and libssh built against libnacl)" );
    version_dep_report += 'Current supported ' + check_type + ' of the remote host:\n\n';
    version_dep_report += join( list:sort( host_supported[check_type] ), sep:'\n' ) + '\n\n';
  }

  if( check_type == "server_host_key_algorithms" && host_supported_items > 0 && in_array( search:"ssh-ed25519", array:libssh_supported[check_type] ) ) {
    version_dep_report += 'Current supported ' + check_type + ' of the scanner:\n\n';
    version_dep_report += join( list:sort( libssh_supported[check_type] ), sep:'\n' ) + '\n\n';
    version_dep_report = str_replace( string:version_dep_report, find:"ssh-ed25519", replace:"ssh-ed25519 (requires libssh >= 0.7.0 on the scanner)" );
    version_dep_report += 'Current supported ' + check_type + ' of the remote host:\n\n';
    version_dep_report += join( list:sort( host_supported[check_type] ), sep:'\n' ) + '\n\n';
  }

  if( check_type == "encryption_algorithms_server_to_client" && host_supported_items > 0 && in_array( search:"chachae20-poly1305", array:libssh_supported[check_type] ) ) {
    version_dep_report += 'Current supported ' + check_type + ' of the scanner:\n\n';
    version_dep_report += join( list:sort( libssh_supported[check_type] ), sep:'\n' ) + '\n\n';
    version_dep_report = str_replace( string:version_dep_report, find:"chachae20-poly1305", replace:"chachae20-poly1305 (requires libssh >= 0.8.0 on the scanner)" );
    version_dep_report += 'Current supported ' + check_type + ' of the remote host:\n\n';
    version_dep_report += join( list:sort( host_supported[check_type] ), sep:'\n' ) + '\n\n';
  }

  if( check_type == "mac_algorithms_server_to_client" && host_supported_items > 0 &&
      ( in_array( search:"hmac-sha2-512", array:libssh_supported[check_type] ) ||
        in_array( search:"hmac-sha2-256", array:libssh_supported[check_type] ) ) ) {
    version_dep_report += 'Current supported ' + check_type + ' of the scanner:\n\n';
    version_dep_report += join( list:sort( libssh_supported[check_type] ), sep:'\n' ) + '\n\n';
    version_dep_report = ereg_replace( string:version_dep_report, pattern:"hmac-sha2-(256|512)", replace:"\0 (requires libssh >= 0.7.0 on the scanner)" );
    version_dep_report += 'Current supported ' + check_type + ' of the remote host:\n\n';
    version_dep_report += join( list:sort( host_supported[check_type] ), sep:'\n' ) + '\n\n';
  }
}

server_banners = get_kb_list( "SSH/server_banner/*" );
if( server_banners ) {
  foreach server_banner( server_banners ) {
    if( "Cisco" >< server_banner )
      cisco_banner = TRUE;
  }
}

if( unsupported_report || version_dep_report || cisco_banner ) {

  report = 'If the SSH credentials are correct the login might have failed because of the following reasons.\n\n';

  if( cisco_banner ) {
    report += "The remote SSH server is a Cisco device and the scanner is using a version < 0.8.5 of the libssh library which has issues with such devices. ";
    report += "See https://www.libssh.org/2018/10/29/libssh-0-8-5-and-libssh-0-7-7/ for more details.";
  }

  if( unsupported_report ) {
    report += "The remote SSH server isn't supporting one of the following algorithms currently required.";
    report += '\n\n' + unsupported_report;
  }

  if( version_dep_report ) {
    report += "The scanner isn't providing the requirements for one of the following algorithms currently required by the remote SSH server.";
    report += '\n\n' + version_dep_report;
  }

  set_kb_item( name:"login/SSH/failed/reason", value:report );
}

log_message( port:port, data:report );
exit( 0 );