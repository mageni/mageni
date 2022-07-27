###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_eyesofnetwork_detect_ssh.nasl 10906 2018-08-10 14:50:26Z cfischer $
#
# Eyes Of Network (EON) Detection (SSH)
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.108166");
  script_version("$Revision: 10906 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 16:50:26 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2017-05-22 09:21:05 +0200 (Mon, 22 May 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Eyes Of Network (EON) Detection (SSH)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (c) 2017 Greenbone Networks GmbH");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("eyesofnetwork/rls");

  script_tag(name:"summary", value:"This script performs SSH based detection of Eyes Of Network (EON).");

  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("ssh_func.inc");
include("host_details.inc");

if( ! rls = get_kb_item( "eyesofnetwork/rls" ) ) exit( 0 );
port = get_kb_item( "eyesofnetwork/ssh/port" );

set_kb_item( name:"eyesofnetwork/detected", value:TRUE );
set_kb_item( name:"eyesofnetwork/ssh/detected", value:TRUE );

version = "unknown";

vers = eregmatch( pattern:"EyesOfNetwork release ([0-9.]+)", string:rls );
if( vers[1] ) {
  version = vers[1];
  set_kb_item( name:"eyesofnetwork/ssh/" + port + "/version", value:version );
  set_kb_item( name:"eyesofnetwork/ssh/" + port + "/concluded", value:rls );
}

exit( 0 );