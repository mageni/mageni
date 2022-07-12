###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_rtsp_os_detection.nasl 10573 2018-07-23 10:44:26Z cfischer $
#
# RTSP Server OS Identification
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
  script_oid("1.3.6.1.4.1.25623.1.0.108451");
  script_version("$Revision: 10573 $");
  script_tag(name:"last_modification", value:"$Date: 2018-07-23 12:44:26 +0200 (Mon, 23 Jul 2018) $");
  script_tag(name:"creation_date", value:"2018-07-23 10:06:14 +0200 (Mon, 23 Jul 2018)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("RTSP Server OS Identification");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH");
  script_dependencies("rtsp_detect.nasl");
  script_mandatory_keys("RTSP/banner/available");

  script_tag(name:"summary", value:"This script performs RTSP server based OS detection.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");

SCRIPT_DESC = "RTSP Server OS Identification";
BANNER_TYPE = "RTSP Server banner";

port = get_kb_item( "Services/rtsp" );
if( ! port ) port = 554;
if( ! get_port_state( port ) ) exit( 0 );
if( ! banner = get_kb_item( "RTSP/" + port + "/Server" ) ) exit( 0 );

# Server: IQinVision Embedded 1.0
if( "IQinVision Embedded" >< banner ) {
  register_and_report_os( os:"Linux/Unix (Embedded)", cpe:"cpe:/o:linux:kernel", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

register_unknown_os_banner( banner:banner, banner_type_name:BANNER_TYPE, banner_type_short:"rtsp_banner", port:port );

exit( 0 );
