###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_vcs_ssh_detect.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# Cisco VCS Detection (SSH)
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105804");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-07-11 11:45:51 +0200 (Mon, 11 Jul 2016)");
  script_name("Cisco TelePresence Video Communication Server Detection (SSH)");

  script_tag(name:"summary", value:"This script performs SSH based detection of Cisco VCS.");

  script_tag(name:"qod_type", value:"package");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("cisco/ssh/vcs");
  exit(0);
}

include("ssh_func.inc");
include("host_details.inc");

if( ! get_kb_item( "cisco/ssh/vcs" ) ) exit( 0 );

sock = ssh_login_or_reuse_connection();
if( ! sock ) exit( 0 );

uname = get_kb_item( "ssh/login/uname" );
if( ! uname || "TANDBERG Video Communication Server" >!< uname ) exit( 0 );

cpe = 'cpe:/a:cisco:telepresence_video_communication_server_software';
vers = 'unknown';

version = eregmatch( pattern:'TANDBERG Video Communication Server X([0-9.]+[^\r\n]+)', string:uname );
if( ! isnull( version[1] ) )
{
  vers = version[1];
  set_kb_item( name:"cisco_vcs/ssh/version", value:vers );
  cpe += ':' + vers;
}

register_product( cpe:cpe, location:'ssh', service:'ssh' );
set_kb_item( name:'cisco_vcs/installed', value:TRUE );

log_message( data: build_detection_report( app:"Cisco TelePresence Video Communication Server",
                                           version:vers,
                                           install:'ssh',
                                           cpe:cpe,
                                           concluded: version[0] ),
             port:0 );

xstatus = ssh_cmd( socket:sock, cmd:'xstatus', return_errors:TRUE, nosh:TRUE, pty:TRUE, timeout:20, retry:20, pattern:'\\*s/end[\r\n]+OK');
if( xstatus )
{
  set_kb_item( name:"cisco_vcs/ssh/xstatus", value:xstatus );
  lines = split( xstatus );
  foreach line ( lines )
  {
    if( line == '*s SystemUnit: /') su = TRUE;
    if( su && line == '*s/end' ) break;

    if( b = eregmatch( pattern:'Build: "([^"]+)"', string:line ) )
    {
      set_kb_item( name:'cisco_vcs/ssh/build', value:b[1]);
      build = b[1];
    }

  }
}

exit( 0 );

