###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_host_id_tag_ssh.nasl 12724 2018-12-09 16:45:47Z cfischer $
#
# Leave Host Identification Tag on scanned host (SSH)
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.108157");
  script_version("$Revision: 12724 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-12-09 17:45:47 +0100 (Sun, 09 Dec 2018) $");
  script_tag(name:"creation_date", value:"2017-05-10 09:37:58 +0200 (Wed, 10 May 2017)");
  script_name("Leave Host Identification Tag on scanned host (SSH)");
  script_category(ACT_END);
  script_family("General");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");

  script_add_preference(name:"Enable", type:"checkbox", value:"no");

  script_tag(name:"summary", value:"This routine leaves a host identification tag
  on a target host for later identification via the Asset Management, provided it
  is a unixoid system offering ssh access with a standard shell.

  The information covers an unique tag created for this specific host. No details
  about the actual scan results are stored on the scanned host.

  By default, this routine is disabled even it is selected to run. To activate
  it, it needs to be explicitly enabled with its corresponding preference switch.

  The file is named gvm_host_id_tag.txt and placed within the home directory (~/) of
  the user which was used to scan the target system.");

  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("ssh_func.inc");
include("misc_func.inc");
include("host_details.inc");

SCRIPT_DESC = "Leave Host Identification Tag on scanned host (SSH)";

enabled = script_get_preference( "Enable" );
if( "yes" >!< enabled ) exit( 0 );

if( get_kb_item( "ssh/no_linux_shell" ) ) {
  log_message( port:0, data:"Target system does not offer a standard shell. Can not continue." );
  exit( 0 );
}

soc = ssh_login_or_reuse_connection();
if( ! soc ) exit( 0 );

# Security token for later use. This token makes sure we're not writing
# into any files we haven't created with this NVT.
file_security_token = "I75k48ddvdbwxLfgZH5DASxpoEVDzV8v";

file = "gvm_host_id_tag.txt";
path = "~/";
path_file = path + file;

dir_exist = ssh_cmd( socket:soc, cmd:"ls -d " + path );
if( "no such file" >< tolower( dir_exist ) ) {
  log_message( port:0, data:"Directory '" + path + "' does not exist. Can not create file '" + path_file + "' and continue." );
  ssh_close_connection();
  exit( 0 );
}

file_exist = ssh_cmd( socket:soc, cmd:"ls -l " + path_file );
if( file_exist =~ "^l[^s]" ) { # don't work on existing symlinks.
  log_message( port:port, data:"File '" + path_file  +  "' is a symbolic link and this is not allowed. Can not continue." );
  ssh_close_connection();
  exit( 0 );
}
if( "permission denied" >< tolower( file_exist ) ) { # No permissions
  log_message( port:port, data:"Permission denied while accessing file '" + path_file  +  "'. Can not continue." );
  ssh_close_connection();
  exit( 0 );
}

if( "no such file" >!< tolower( file_exist ) ) { # if the file already exist...

  current_content = ssh_cmd( socket:soc, cmd:"cat " + path_file ); # look what is in it...

  if( strlen( current_content ) > 0 ) {

    if( file_security_token >!< current_content ) {
      # no security_token or not created by this nvt
      log_message( port:port, data:"Security Token '" + file_security_token  + "' not found in existing file '" + path_file + "'. Can not continue." );
      ssh_close_connection();
      exit( 0 );
    } else {
      host_id = eregmatch( pattern:"<host_id>(.*)</host_id>", string:current_content );
      if( host_id[1] ) {
        register_host_detail( name:"Host-ID-Tag", value:host_id[1], desc:SCRIPT_DESC );
        log_message( port:0, data:"Host id tag '" + host_id[1] + "' successfully collected from '" + path_file  + "'." );
      } else {
        log_message( port:0, data:"Failed to collect host id tag from '" + path_file  + "'. Possible malformed/invalid file." );
      }
    }
  } else {
    log_message( port:0, data:"Empty response received while trying to collect host id tag from '" + path_file  + "'." );
  }
} else { # create the file if it doesn't exist

  # This is the Host ID Tag which is later also sent as a host detail
  rand = rand_str( length:32 );

  cmd = "echo '";
  cmd += '<token>' + file_security_token + '</token>\n';
  cmd += '<host_id>' + rand + "</host_id>'";
  cmd += '>' + path_file + ' ; echo $?';

  create_request = ssh_cmd( socket:soc, cmd:cmd );

  new_content = ssh_cmd( socket:soc, cmd:"cat " + path_file );
  if( "<token>" >!< new_content && "<host_id>" >!< new_content ) {
    log_message( port:0, data:"Sending host id tag to '" + path_file + "' failed. Response: " + create_request );
  } else {
    register_host_detail( name:"Host-ID-Tag", value:rand, desc:SCRIPT_DESC );
    log_message( port:0, data:"Host id tag '" + rand + "' successfully send to '" + path_file  + "'." );
  }
}

ssh_close_connection();

exit( 0 );