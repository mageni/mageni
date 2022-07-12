###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_nx_os_CSCuw13560.nasl 11872 2018-10-12 11:22:41Z cfischer $
#
# Cisco NX-OS Nexus 9000 (N9K) Series Switch Reserved VLAN Tag Vulnerability
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105377");
  script_bugtraq_id(76762);
  script_cve_id("CVE-2015-6295");
  script_tag(name:"cvss_base", value:"4.8");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:P/I:N/A:P");
  script_version("$Revision: 11872 $");

  script_name("Cisco NX-OS Software TACACS+ Server Local Privilege Escalation Vulnerability");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/viewAlert.x?alertId=40990");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:22:41 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-09-21 11:41:15 +0200 (Mon, 21 Sep 2015)");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"Workaround");

  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("gb_cisco_nx_os_version.nasl");
  script_mandatory_keys("cisco_nx_os/version", "cisco_nx_os/model", "cisco_nx_os/device");

  script_tag(name:"impact", value:"An unauthenticated, adjacent attacker could exploit this vulnerability to cause a DoS condition. A successful exploit may also impact confidentiality due to errors in handling network packets.");
  script_tag(name:"vuldetect", value:"Check the NX OS version.");
  script_tag(name:"insight", value:"This issue is being tracked by Cisco Bug ID CSCuw13560");
  script_tag(name:"solution", value:"See the vendor advisory for a solution");
  script_tag(name:"summary", value:"Cisco Nexus 9000 Series Switches contain a vulnerability that could allow an unauthenticated, adjacent attacker to cause a denial of service condition.");
  script_tag(name:"affected", value:"Nexus 9000 Series 7.0(3)I1(1) and 6.1(2)I3(4)");
  exit(0);
}

if( ! device = get_kb_item( "cisco_nx_os/device" ) ) exit( 0 );
if( "Nexus" >!< device ) exit( 0 );

if ( ! nx_model = get_kb_item( "cisco_nx_os/model" ) )   exit( 0 );
if ( nx_model !~ '^N9K' ) exit( 99 );

if ( ! nx_ver   = get_kb_item( "cisco_nx_os/version" ) ) exit( 0 );

if ( nx_ver  == "6.1(2)I3(4)" || nx_ver == "7.0(3)I1(1)" )
{
  security_message( port:0, data:'Installed Version: ' + nx_ver + '\nFixed Version:     NA' );
  exit( 0 );
}

exit( 99 );

