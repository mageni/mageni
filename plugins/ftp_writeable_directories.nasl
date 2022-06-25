###############################################################################
# OpenVAS Vulnerability Test
# $Id: ftp_writeable_directories.nasl 13611 2019-02-12 15:23:02Z cfischer $
#
# FTP Writeable Directories
#
# Authors:
# Tenable Network Security
#
# Copyright:
# Copyright (C) 2006 TNS
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
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
  script_oid("1.3.6.1.4.1.25623.1.0.19782");
  script_version("$Revision: 13611 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-12 16:23:02 +0100 (Tue, 12 Feb 2019) $");
  script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("FTP Writeable Directories");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2006 TNS");
  script_family("FTP");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/banner/available", "ftp/anonymous_ftp/detected");

  script_tag(name:"summary", value:"The remote FTP server contains world-writeable files.

  By crawling through the remote FTP server, several directories
  where marked as being world writeable.");

  script_tag(name:"impact", value:"An attacker may use this misconfiguration problem to use the
  remote FTP server to host arbitrary data, including possibly
  illegal content (ie: Divx movies, etc...).");

  script_tag(name:"solution", value:"Configure the remote FTP directories so that they are not
  world-writeable.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("ftp_func.inc");
include("misc_func.inc");

global_var CheckedDir;
global_var WriteableDirs;
global_var Mode;
global_var Saved_in_KB;

MODE_WRITE 		= 1;
MODE_CHECK_PERM 	= 2;

if( safe_checks() ) {
  Mode = MODE_CHECK_PERM;
} else  {
  Mode = MODE_WRITE;
}

# nb: Don't use ftp/login or ftp_get_kb_creds as both might contain a different user
login = get_kb_item( "ftp/anonymous/login" );
pwd   = get_kb_item( "ftp/anonymous/password" );

function crawl_dir( socket, directory, level ) {

  local_var port, soc2, r, dirs, array, dir, sep, str, alreadyadded;
  if( level > 20 ) return 0;

  if( directory[strlen( directory ) - 1] == "/" ) {
    sep = "";
  } else {
    sep = "/";
  }

  if( CheckedDir[directory] ) return 0;
  port = ftp_pasv( socket:socket );
  if( ! port ) return 0;
  soc2 = open_sock_tcp( port );
  if( ! soc2 ) return 0;
  dirs = make_list();

  alreadyadded = 0;
  if( Mode == MODE_WRITE ) {
    vt_strings = get_vt_strings();
    str = vt_strings["default_rand"];
    send( socket:socket, data:'MKD ' + directory + sep + str  + '\r\n' );
    r = ftp_recv_line( socket:socket );
    if( r[0] == '2' ) {
      WriteableDirs[directory] = 1;
      send( socket:socket, data:'RMD ' + directory + sep + str + '\r\n' );
      r = ftp_recv_line( socket:socket );
      if( ! Saved_in_KB ) {
        set_kb_item(name:"ftp/writeable_dir", value:directory);
        Saved_in_KB++;
        alreadyadded = 1;
      }
    }
  }

  send( socket:socket, data:'LIST ' + directory + '\r\n' );
  CheckedDir[directory] = 1;

  r = ftp_recv_line( socket:socket );
  if( r[0] != '1' ) {
    close( soc2 );
    return 0;
  }

  while( TRUE ) {
    r = recv_line( socket:soc2, length:4096 );
    if( ! r ) break;
    if( r[0] == 'd' ) {
      array = eregmatch(pattern:"([drwxtSs-]*) *([0-9]*) ([0-9]*) *([^ ]*) *([0-9]*) ([^ ]*) *([^ ]*) *([^ ]*) (.*)", string:chomp(r));
      if( max_index(array) >= 9 ) {
#       if ( Mode == MODE_CHECK_PERM ) {
        if( array[1] =~ "^d.......w." ) {
          if( alreadyadded == 0 ) {
            WriteableDirs[directory + sep + array[9]] = 1;
            if( ! Saved_in_KB ) {
              set_kb_item( name:"ftp/writeable_dir", value:directory + sep + array[9] );
              Saved_in_KB++;
            }
          }
        }
#       }
        if( array[9] != "." && array[9] != ".." )
          dirs = make_list( dirs, directory + sep + array[9] );
      }
    }
  }
  close( soc2 );
  r = recv_line( socket:socket, length:4096 );
  foreach dir( dirs ) {
    crawl_dir( socket:socket, directory:dir, level:level + 1 );
  }
  return 0;
}

port = get_ftp_port( default:21 );
if( ! get_kb_item( "ftp/" + port + "/anonymous" ) ) exit( 0 );

soc = open_sock_tcp( port );
if( ! soc ) exit( 0 );
if( ! ftp_authenticate( socket:soc, user:login, pass:pwd ) ) exit( 0 );

crawl_dir( socket:soc, directory:"/", level:0 );
ftp_close( socket:soc );

if( isnull( WriteableDirs ) ) exit( 0 );

foreach dir( keys( WriteableDirs ) ) {
  report += ' - ' + dir + '\n';
}

if( report ) {
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );