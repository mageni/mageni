###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_show_version.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# Cisco show version
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
  script_oid("1.3.6.1.4.1.25623.1.0.105531");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-01-27 10:22:48 +0100 (Wed, 27 Jan 2016)");
  script_name("Cisco show version");

  script_tag(name:"summary", value:"This script execute 'show version' on the target and store the result in the KB for later use");
  script_tag(name:"qod_type", value:"package");

  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("cisco/detected");
  exit(0);
}

include("ssh_func.inc");

if( ! get_kb_item("cisco/detected") ) exit( 0 );

sock = ssh_login_or_reuse_connection();
if( ! sock ) exit( 0 );

system = ssh_cmd( socket:sock, cmd:'show version\n', nosh:TRUE );

if( "Error getting tty" >< system )
  system = ssh_cmd( socket:sock, cmd:'show version\n', nosh:TRUE, pty:TRUE );

close( sock );

if( system ) set_kb_item( name:"cisco/show_version", value:system );

exit( 0 );

