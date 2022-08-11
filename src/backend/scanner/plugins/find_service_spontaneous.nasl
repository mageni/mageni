# Copyright (C) 2020 Greenbone Networks GmbH
# Older service detection pattern were moved from find_service1.nasl
# into this VT, and are Copyright (C) by the respective right holder(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.108747");
  script_version("2020-04-14T13:21:36+0000");
  script_tag(name:"last_modification", value:"2020-04-15 10:04:41 +0000 (Wed, 15 Apr 2020)");
  script_tag(name:"creation_date", value:"2020-04-14 11:32:00 +0000 (Tue, 14 Apr 2020)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Service Detection from 'spontaneous' Banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Service detection");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/unknown");

  script_tag(name:"summary", value:"This plugin performs service detection.

  This plugin is a complement of find_service.nasl. It evaluates 'spontaneous' banners
  sent by the remaining unknown services and tries to identify them.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");
include("ssh_func.inc");

if( ! port = get_kb_item( "Services/unknown" ) )
  exit( 0 );

if( ! get_port_state( port ) )
  exit( 0 );

if( ! service_is_unknown( port:port ) )
  exit( 0 );

key = "FindService/tcp/" + port + "/spontaneous";
banner = get_kb_item( key );
if( strlen( banner ) <= 0 ) {
  # nb: At least STelnet of Huawei VRP devices doesn't respond to the banner
  # grabbing of nasl_builtin_find_service.c but providing a banner with a
  # separate recv_line() so we're trying to grab it here again.

  soc = open_sock_tcp( port );
  if( ! soc )
    exit( 0 );

  banner = recv_line( socket:soc, length:4096 );
  close( soc );

  if( strlen( banner ) > 0 ) {
    set_kb_item( name:key, value:banner );
    bannerhex = hexstr( banner );
    if( '\0' >< banner )
      set_kb_item( name:key + "Hex", value:bannerhex );
  }
} else {
  bannerhex = hexstr( banner );
}

if( strlen( banner ) <= 0 )
  exit( 0 );

if( banner =~ '^[0-9]+ *, *[0-9]+ *: *USERID *: *UNIX *: *[a-z0-9]+' ) {
  register_service( port:port, proto:"fake-identd" );
  set_kb_item( name:"fake_identd/" + port, value:TRUE );
  exit( 0 );
}

# Running on 6600, should be handled already later by find_service2.nasl
# but the banner sometimes is also coming in "spontaneous".
# 00: 3c 3f 78 6d 6c 20 76 65 72 73 69 6f 6e 3d 22 31    <?xml version="1
# 10: 2e 30 22 20 65 6e 63 6f 64 69 6e 67 3d 22 49 53    .0" encoding="IS
# 20: 4f 2d 38 38 35 39 2d 31 22 20 73 74 61 6e 64 61    O-8859-1" standa
# 30: 6c 6f 6e 65 3d 22 79 65 73 22 3f 3e 0a 3c 21 44    lone="yes"?>.<!D
# 40: 4f 43 54 59 50 45 20 47 41 4e 47 4c 49 41 5f 58    OCTYPE GANGLIA_X
# 50: 4d 4c 20 5b 0a 20 20 20 3c 21 45 4c 45 4d 45 4e    ML [.   <!ELEMEN
# 60: 54 20 47 41 4e 47 4c 49 41 5f 58 4d 4c 20 28 47    T GANGLIA_XML (G
# 70: 52 49 44 29 2a 3e 0a 20 20 20 20 20 20 3c 21 41    RID)*>.      <!A
if( match( string:banner, pattern:'<?xml version=*' ) && " GANGLIA_XML " >< banner &&
    "ATTLIST HOST GMOND_STARTED" >< banner ) {
  register_service( port:port, proto:"gmond" );
  log_message( port:port, data:"Ganglia monitoring daemon seems to be running on this port" );
  exit( 0 );
}

if( match( string:banner, pattern:'CIMD2-A ConnectionInfo: SessionId = * PortId = *Time = * AccessType = TCPIP_SOCKET PIN = *' ) ) {
  report_service( port:port, svc:"smsc" );
  exit( 0 );
}

# 00: 57 65 64 20 4a 75 6c 20 30 36 20 31 37 3a 34 37 Wed Jul 06 17:47
# 10: 3a 35 38 20 4d 45 54 44 53 54 20 32 30 30 35 0d :58 METDST 2005.
# 20: 0a .
if( ereg( pattern:"^(Mon|Tue|Wed|Thu|Fri|Sat|Sun|Lun|Mar|Mer|Jeu|Ven|Sam|Dim) (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|D[eé]c|F[eé]v|Avr|Mai|Ao[uû]) *(0?[0-9]|[1-3][0-9]) [0-9]+:[0-9]+(:[0-9]+)?( *[ap]m)?( +[A-Z]+)? [1-2][0-9][0-9][0-9].?.?$", string:banner ) ) {
  report_service( port:port, svc:"daytime" );
  exit( 0 );
}

# Possible outputs:
# |/dev/hdh|Maxtor 6Y160P0|38|C|
# |/dev/hda|ST3160021A|UNK|*||/dev/hdc|???|ERR|*||/dev/hdg|Maxtor 6B200P0|UNK|*||/dev/hdh|Maxtor 6Y160P0|38|C|
if( banner =~ '^(\\|/dev/[a-z0-9/-]+\\|[^|]*\\|[^|]*\\|[^|]\\|)+$' ) {
  report_service( port:port, svc:"hddtemp" );
  exit( 0 );
}

if( match( string:banner, pattern:'220 *FTP Server ready\r\n', icase:TRUE ) ||
    match( string:banner, pattern:'220 *FTP Server ready.\r\n', icase:TRUE ) ) { # e.g. 220 AP9630 Network Management Card AOS v6.0.6 FTP server ready.
  report_service( port:port, svc:"ftp" );
  exit( 0 );
}

# 00: 22 49 4d 50 4c 45 4d 45 4e 54 41 54 49 4f 4e 22 "IMPLEMENTATION"
# 10: 20 22 43 79 72 75 73 20 74 69 6d 73 69 65 76 65  "Cyrus timsieve
# 20: 64 20 76 32 2e 32 2e 33 22 0d 0a 22 53 41 53 4c d v2.2.3".."SASL
# 30: 22 20 22 50 4c 41 49 4e 22 0d 0a 22 53 49 45 56 " "PLAIN".."SIEV
# 40: 45 22 20 22 66 69 6c 65 69 6e 74 6f 20 72 65 6a E" "fileinto rej
# 50: 65 63 74 20 65 6e 76 65 6c 6f 70 65 20 76 61 63 ect envelope vac
# 60: 61 74 69 6f 6e 20 69 6d 61 70 66 6c 61 67 73 20 ation imapflags
# 70: 6e 6f 74 69 66 79 20 73 75 62 61 64 64 72 65 73 notify subaddres
# 80: 73 20 72 65 6c 61 74 69 6f 6e 61 6c 20 72 65 67 s relational reg
# 90: 65 78 22 0d 0a 22 53 54 41 52 54 54 4c 53 22 0d ex".."STARTTLS".
# a0: 0a 4f 4b 0d 0a .OK..
if( match( string:banner, pattern:'"IMPLEMENTATION" "Cyrus timsieved v*"*"SASL"*' ) ) {
  register_service( port:port, proto:"sieve", message:"Sieve mail filter daemon seems to be running on this port." );
  log_message( port:port, data:"Sieve mail filter daemon seems to be running on this port." );
  exit( 0 );
}

# I'm not sure it should go here or in find_service2...
if( match( string:banner, pattern:'220 Axis Developer Board*' ) ) {
  report_service( port:port, svc:"axis-developer-board" );
  exit( 0 );
}

if( match( string:banner, pattern:'  \x5f\x5f\x5f           *Copyright (C) * Eggheads Development Team' ) ) {
  report_service( port:port, svc:"eggdrop" );
  exit( 0 );
}

# Music Player Daemon from www.musicpd.org
if( ereg( string:banner, pattern:'^OK MPD [0-9.]+\n' ) ) {
  report_service( port:port, svc:"mpd" );
  exit( 0 );
}

if( egrep( pattern:"^OK WorkgroupShare.*server ready", string:banner ) ) {
  report_service( port:port, svc:"WorkgroupShare" );
  exit( 0 );
}

# Eudora Internet Mail Server ACAP server.
if( "* Eudora-SET (IMPLEMENTATION Eudora Internet Mail Server" >< banner ) {
  report_service( port:port, svc:"acap" );
  exit( 0 );
}

# Sophos Remote Messaging / Management Server
if( "IOR:010000002600000049444c3a536f70686f734d6573736167696e672f4d657373616765526f75746572" >< banner ) {
  register_service( port:port, proto:"sophos_rms", message:"A Sophos Remote Messaging / Management Server seems to be running on this port." );
  log_message( port:port, data:"A Sophos Remote Messaging / Management Server seems to be running on this port." );
  exit( 0 );
}

if( banner =~ '^\\* *BYE ' ) {
  report_service( port:port, svc:"imap", banner:banner, message:"The IMAP server rejects connection from our host. We cannot test it." );
  log_message( port:port, data:"The IMAP server rejects connection from our host. We cannot test it." );
  exit( 0 );
}

# General case should be handled by find_service_3digits
if( match( string:banner, pattern:'200 CommuniGatePro PWD Server * ready*' ) ) {
  report_service( port:port, svc:"pop3pw" );
  exit( 0 );
}

# Should be handled by find_service already
if( banner =~ "^RFB [0-9]") {
  report_service( port:port, svc:"vnc" );
  replace_kb_item( name:"vnc/banner/" + port, value:banner );
  exit( 0 );
}

# https://www.iana.org/assignments/beep-parameters/beep-parameters.xhtml
# 0x00:  52 50 59 20 30 20 30 20 2E 20 30 20 31 30 32 0D    RPY 0 0 . 0 102.
# 0x10:  0A 43 6F 6E 74 65 6E 74 2D 54 79 70 65 3A 20 61    .Content-Type: a
# 0x20:  70 70 6C 69 63 61 74 69 6F 6E 2F 62 65 65 70 2B    pplication/beep+
# 0x30:  78 6D 6C 0D 0A 0D 0A 3C 67 72 65 65 74 69 6E 67    xml....<greeting
# 0x40:  3E 3C 70 72 6F 66 69 6C 65 20 75 72 69 3D 22 68    ><profile uri="h
# 0x50:  74 74 70 3A 2F 2F 69 61 6E 61 2E 6F 72 67 2F 62    ttp://iana.org/b
# 0x60:  65 65 70 2F 54 4C 53 22 2F 3E 3C 2F 67 72 65 65    eep/TLS"/></gree
# 0x70:  74 69 6E 67 3E 0D 0A 45 4E 44 0D 0A                ting>..END..
#
# nb: beep/xmlrpc has application/xml as the Content-Type so using some
# different patterns here.
# nb: Have seen a response to http_get and spontaneuos for this so the same check is
# done in find_service1.nasl as well. Please keep both in sync.
if( ( banner =~ "^RPY [0-9] [0-9]" && "Content-Type: application/" >< banner ) ||
    ( "<profile uri=" >< banner && "http://iana.org/beep/" >< banner ) ||
    "Content-Type: application/beep" >< banner ) {
  register_service( port:port, proto:"beep", message:"A service supporting the Blocks Extensible Exchange Protocol (BEEP) seems to be running on this port." );
  log_message( port:port, data:"A service supporting the Blocks Extensible Exchange Protocol (BEEP) seems to be running on this port." );
  exit( 0 );
}

if( ssh_verify_server_ident( data:banner ) ) {
  register_service( port:port, proto:"ssh", message:"A SSH service seems to be running on this port." );
  log_message( port:port, data:"A SSH service seems to be running on this port." );
  replace_kb_item( name:"SSH/server_banner/" + port, value:chomp( banner ) );
}

# Keep qotd at the end of the list, as it may generate false detection
if( banner =~ '^"[^"]+"[ \t\r\n]+[A-Za-z -]+[ \t\r\n]+\\([0-9]+(-[0-9]+)?\\)[ \t\r\n]+$' ) {
  register_service( port:port, proto:"qotd", message:"qotd seems to be running on this port." );
  log_message( port:port, data:"qotd seems to be running on this port." );
  exit( 0 );
}

exit( 0 );
