###############################################################################
# OpenVAS Vulnerability Test
# $Id: nmap_nse_net.nasl 9633 2018-04-26 14:07:08Z jschulte $
#
# Launch Nmap NSE net Tests
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.108083");
  script_version("$Revision: 9633 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-26 16:07:08 +0200 (Thu, 26 Apr 2018) $");
  script_tag(name:"creation_date", value:"2017-02-19 16:08:05 +0100 (Sun, 19 Feb 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Launch Nmap NSE net Tests");
  script_category(ACT_INIT);
  script_copyright("Copyright (c) 2017 Greenbone Networks GmbH");
  script_family("Nmap NSE net");
  script_dependencies("toolcheck.nasl");
  script_mandatory_keys("Tools/Present/nmap");

  script_add_preference(name:"Launch Nmap NSE net Tests", type:"checkbox", value:"no");

  script_tag(name:"summary", value:"This script controls the execution of Nmap NSE net Tests");

  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

launch_nmap_nse_net = script_get_preference( "Launch Nmap NSE net Tests" );
if( launch_nmap_nse_net == "yes" ) {
  set_kb_item( name:"Tools/Launch/nmap_nse_net", value:TRUE );
}

exit( 0 );