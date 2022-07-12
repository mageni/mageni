###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_nx_os_63732.nasl 11867 2018-10-12 10:48:11Z cfischer $
#
# Cisco Nexus 1000V Local Arbitrary Command Execution Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.105109");
  script_bugtraq_id(63732);
  script_cve_id("CVE-2013-5556");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_version("$Revision: 11867 $");

  script_name("Cisco Nexus 1000V  Local Arbitrary Command Execution Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/63732");
  script_xref(name:"URL", value:"https://tools.cisco.com/bugsearch/bug/CSCui21340");

  script_tag(name:"impact", value:"Local authenticated attackers can exploit this issue to execute
arbitrary commands on the underlying operating system.");

  script_tag(name:"vuldetect", value:"Check the NX OS version.");
  script_tag(name:"insight", value:"This issue is being tracked by Cisco bug ID CSCui21340.");

  script_tag(name:"solution", value:"Updates are available.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"Cisco Nexus 1000V is prone to a local arbitrary command-execution
vulnerability.");
  script_tag(name:"affected", value:"Cisco Nexus 1000V");


  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:48:11 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-11-05 16:22:05 +0100 (Wed, 05 Nov 2014)");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("CISCO");
  script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("gb_cisco_nx_os_version.nasl");
  script_mandatory_keys("cisco_nx_os/version", "cisco_nx_os/model", "cisco_nx_os/device");

  exit(0);
}

if( ! device = get_kb_item( "cisco_nx_os/device" ) ) exit( 0 );
if( "Nexus" >!< device ) exit( 0 );

if ( ! nx_model = get_kb_item( "cisco_nx_os/model" ) )   exit( 0 );
if ( ! nx_ver   = get_kb_item( "cisco_nx_os/version" ) ) exit( 0 );

if( '1000V' >!< nx_model ) exit( 99 );

affected = make_list(
                     "4.0(4)SV1(1)",
                     "4.0(4)SV1(2)",
                     "4.0(4)SV1(3)",
                     "4.0(4)SV1(3a)",
                     "4.0(4)SV1(3b)",
                     "4.0(4)SV1(3c)",
                     "4.0(4)SV1(3d)",
                     "4.2(1)SV1(4)",
                     "4.2(1)SV1(4a)",
                     "4.2(1)SV1(4b)",
                     "4.2(1)SV1(5.1)",
                     "4.2(1)SV1(5.1a)",
                     "4.2(1)SV1(5.2)",
                     "4.2(1)SV1(5.2b)",
                     "5.2(1)SM1(5.1)",
                     "4.2(1) VSG1(1)"
                    );

foreach affected_nx_ver ( affected )
{
  if( nx_ver == affected_nx_ver )
  {
     security_message( port:0 );
     exit( 0 );
  }
}

exit( 99 );

