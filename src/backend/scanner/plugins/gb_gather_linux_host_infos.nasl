###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_gather_linux_host_infos.nasl 12723 2018-12-09 16:32:25Z cfischer $
#
# Gather Linux Host Information
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.105525");
  script_version("$Revision: 12723 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-09 17:32:25 +0100 (Sun, 09 Dec 2018) $");
  script_tag(name:"creation_date", value:"2016-01-22 13:42:01 +0100 (Fri, 22 Jan 2016)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Gather Linux Host Information");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gather-package-list.nasl", "os_detection.nasl");
  script_mandatory_keys("login/SSH/success", "Host/runs_unixoide");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"This script attempts to gather some information like the 'uptime'
  from a linux host and stores the results in the KB.");

  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("host_details.inc");
include("ssh_func.inc");

sock = ssh_login_or_reuse_connection( );
if( ! sock ) exit( 0 );

uptime = ssh_cmd( socket:sock, cmd:'cat /proc/uptime' );

if( uptime && uptime =~ "^[0-9]+\.[0-9]+" ) {

  now = unixtime();

  ut = split( uptime, sep:".", keep:FALSE );
  uptime = int( ut[0] );

  t_now = ( now - uptime );

  register_host_detail( name:"uptime", value:t_now );
  set_kb_item( name:"Host/uptime", value:t_now );
}

uname = get_kb_item( "Host/uname" );

if( uname && "Linux" >< uname ) {

  un = split( uname );
  foreach line( un ) {

    if( line =~ "^Linux" ) {

      kv = eregmatch( pattern:'^Linux [^ ]+ ([^ ]+) #([0-9])+', string:line );

      if( ! isnull( kv[1] ) ) {
        set_kb_item( name:"Host/running_kernel_version", value:kv[1] );
        register_host_detail( name:"Running-Kernel", value:kv[1] );
      }

      if( ! isnull( kv[2] ) )
        set_kb_item( name:"Host/running_kernel_build_version", value:kv[2] );

      break;
    }
  }
}

close( sock );

exit( 0 );