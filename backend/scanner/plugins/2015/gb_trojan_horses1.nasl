###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_trojan_horses1.nasl 9337 2018-04-05 14:12:37Z cfischer $
#
# Possible Trojan Horses
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2015 Greenbone Networks GmbH
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
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105237");
  script_version("$Revision: 9337 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-05 16:12:37 +0200 (Thu, 05 Apr 2018) $");
  script_tag(name:"creation_date", value:"2015-03-16 10:53:07 +0100 (Mon, 16 Mar 2015)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Possible Trojan Horses");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Malware");
  script_dependencies("find_service2.nasl");
  script_mandatory_keys("possible-trojan/installed");

  script_tag(name:"summary", value:"Look for potential trojan horses.");

  script_tag(name:"solution", value:"Clean up the target host from the potential trojan horse.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

if( port = get_kb_item( "possible-trojan/installed" ) ) {
  name = get_kb_item( "trojan/installed/name" );
  security_message( port:port, data:"A trojan horse (" + name + ") seems to be running on this port." );
  exit( 0 );
}

exit( 99 );
