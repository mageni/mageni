###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hyperip_ssh_login_detect.nasl 10898 2018-08-10 13:38:13Z cfischer $
#
# NetEx HyperIP Detection (SSH-Login)
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.108351");
  script_version("$Revision: 10898 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 15:38:13 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2018-02-26 12:49:56 +0100 (Mon, 26 Feb 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("NetEx HyperIP Detection (SSH-Login)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("hyperip/ssh-login/show_version_or_uname");

  script_tag(name:"summary", value:"This script performs SSH login based detection of a NetEx HyperIP
  virtual appliance.");

  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("ssh_func.inc");
include("host_details.inc");

if( ! get_kb_item( "hyperip/ssh-login/show_version_or_uname" ) ) exit( 0 );

version = "unknown";

port = get_kb_item( "hyperip/ssh-login/port" );

show_version = get_kb_item( "hyperip/ssh-login/" + port + "/show_version" );
uname        = get_kb_item( "hyperip/ssh-login/" + port + "/uname" );

if( ! show_version && ! uname ) exit( 0 );

# Product Version ............ HyperIP 6.1.1 11-Jan-2018 13:09 (build 2) (r9200)
vers = eregmatch( pattern:"Product Version([^\n]+)HyperIP ([0-9.]+)", string:show_version );
if( vers[2] ) {
  version = vers[2];
  set_kb_item( name:"hyperip/ssh-login/" + port + "/concluded", value:vers[0] + " from 'showVersion' command" );
} else {
  set_kb_item( name:"hyperip/ssh-login/" + port + "/concluded", value:uname );
}

# nb: hyperip/ssh-login/port is already set in gather-package-list.nasl
set_kb_item( name:"hyperip/detected", value:TRUE );
set_kb_item( name:"hyperip/ssh-login/detected", value:TRUE );
set_kb_item( name:"hyperip/ssh-login/" + port + "/version", value:version );

exit( 0 );