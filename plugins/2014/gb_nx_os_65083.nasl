###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_nx_os_65083.nasl 11867 2018-10-12 10:48:11Z cfischer $
#
# Cisco NX-OS Software TACACS+ Server Local Privilege Escalation Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2014 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.103889");
  script_bugtraq_id(65083);
  script_cve_id("CVE-2014-0676");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_version("$Revision: 11867 $");

  script_name("Cisco NX-OS Software TACACS+ Server Local Privilege Escalation Vulnerability");


  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65083");
  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityNotice/CVE-2014-0676");

  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:48:11 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-01-23 12:43:53 +0100 (Thu, 23 Jan 2014)");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("CISCO");
  script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("gb_cisco_nx_os_version.nasl");
  script_mandatory_keys("cisco_nx_os/version", "cisco_nx_os/model", "cisco_nx_os/device");

  script_tag(name:"impact", value:"A local attacker can exploit this issue to execute arbitrary
commands with elevated privileges.");
  script_tag(name:"vuldetect", value:"Check the NX OS version.");
  script_tag(name:"insight", value:"This issue is being tracked by Cisco Bug ID CSCum47367.");
  script_tag(name:"solution", value:"Ask the Vendor for an update.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"Cisco NX-OS is prone to a local privilege-escalation vulnerability.");
  script_tag(name:"affected", value:"Cisco Nexus 7000 Series Switches running NX-OS 6.1(4)");

  exit(0);
}

if( ! device = get_kb_item( "cisco_nx_os/device" ) ) exit( 0 );
if( "Nexus" >!< device ) exit( 0 );

if ( ! nx_model = get_kb_item( "cisco_nx_os/model" ) )   exit( 0 );
if ( ! nx_ver   = get_kb_item( "cisco_nx_os/version" ) ) exit( 0 );

if ( nx_model !~ "^7" )exit(99);

if ( nx_ver  == "6.1(4)" )
{
  security_message(port:0, data:'Installed Version: ' + nx_ver + '\nFixed Version:     NA');
  exit(0);
}

exit(99);
