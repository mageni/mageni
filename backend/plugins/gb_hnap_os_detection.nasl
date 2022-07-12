###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hnap_os_detection.nasl 12432 2018-11-20 09:58:47Z cfischer $
#
# Home Network Administration Protocol (HNAP) OS Identification
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
  script_oid("1.3.6.1.4.1.25623.1.0.108284");
  script_version("$Revision: 12432 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-20 10:58:47 +0100 (Tue, 20 Nov 2018) $");
  script_tag(name:"creation_date", value:"2017-10-27 07:13:48 +0200 (Fri, 27 Oct 2017)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Home Network Administration Protocol (HNAP) OS Identification");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("gb_hnap_detect.nasl");
  script_mandatory_keys("HNAP/port");

  script_tag(name:"summary", value:"This script performs Home Network Administration Protocol (HNAP) based OS detection.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");

SCRIPT_DESC = "HNAP OS Identification";
BANNER_TYPE = "HNAP device info";

if( ! port = get_kb_item( "HNAP/port" ) ) exit( 0 );
vendor = get_kb_item( "HNAP/" + port + "/vendor" );
model  = get_kb_item( "HNAP/" + port + "/model" );

# e.g. SMC Inc. SMCWBR14S
# or Linksys E1200
banner = vendor + " " + model;
if( ! banner || strlen( banner ) <= 1 )  exit( 0 );

if( "SMC Inc. SMCWBR14S" >< banner || "Linksys E1200" >< banner ) {
  register_and_report_os( os:"Linux/Unix", cpe:"cpe:/o:linux:kernel", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# e.g. D-Link DIR-868L
if( banner =~ "^D-Link (DAP|DIR|DNS|DSL|DWR)" ) {
  register_and_report_os( os:"Linux/Unix", cpe:"cpe:/o:linux:kernel", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

register_unknown_os_banner( banner:banner, banner_type_name:BANNER_TYPE, banner_type_short:"hnap_device_info", port:port );

exit( 0 );