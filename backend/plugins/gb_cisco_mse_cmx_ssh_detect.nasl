###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_mse_cmx_ssh_detect.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# Cisco Mobility Service Engine Detection (SSH)
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
  script_oid("1.3.6.1.4.1.25623.1.0.105462");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-11-20 12:48:40 +0100 (Fri, 20 Nov 2015)");
  script_name("Cisco Mobility Service Engine Detection (SSH)");

  script_tag(name:"summary", value:"This script performs SSH based detection of Cisco Mobility Service Engine");

  script_tag(name:"qod_type", value:"package");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("cisco_mse/status");
  exit(0);
}

status = get_kb_item("cisco_mse/status");

if( ! status || ( "Cisco Mobility Service Engine" >!< status && "Build Version" >!< status ) ) exit( 0 );

if( "Product name: Cisco Mobility Service Engine" >< status )
  version = eregmatch( pattern:'Product name: Cisco Mobility Service Engine[\r\n]+Version: ([^\r\n]+)', string:status );
else
  version = eregmatch( pattern:'Build Version\\s*:\\s*([0-9]+[^\r\n]+)', string:status );

if( ! isnull( version[1] ) )
{
  set_kb_item( name:"cisco_mse/ssh/version", value:version[1] );
  set_kb_item( name:"cisco_mse/lsc", value:TRUE );
  vers = version[1];
}

exit( 0 );
