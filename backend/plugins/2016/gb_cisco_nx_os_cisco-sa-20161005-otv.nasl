###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_nx_os_cisco-sa-20161005-otv.nasl 12431 2018-11-20 09:21:00Z asteins $
#
# Cisco Nexus 7000 and 7700 Series Switches Overlay Transport Virtualization Buffer Overflow Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
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

CPE = "cpe:/o:cisco:nx-os";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106340");
  script_cve_id("CVE-2016-1453");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_version("$Revision: 12431 $");

  script_name("Cisco Nexus 7000 and 7700 Series Switches Overlay Transport Virtualization Buffer Overflow Vulnerability");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20161005-otv");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"Upgrade to 7.2(2)D1(1) or later.");

  script_tag(name:"summary", value:"A vulnerability in the Overlay Transport Virtualization (OTV) generic
routing encapsulation (GRE) implementation of the Cisco Nexus 7000 and 7700 Series Switches could allow an
unauthenticated, adjacent attacker to cause a reload of the affected system or to remotely execute code.");

  script_tag(name:"insight", value:"The vulnerability is due to incomplete input validation performed on the
size of OTV packet header parameters, which can result in a buffer overflow. An attacker could exploit this
vulnerability by sending a crafted OTV UDP packet to the OTV interface on an affected device.");

  script_tag(name:"impact", value:"An exploit could allow the attacker to execute arbitrary code and obtain
full control of the system or cause a reload of the OTV related process on the affected device.");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"$Date: 2018-11-20 10:21:00 +0100 (Tue, 20 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-10-06 11:57:56 +0700 (Thu, 06 Oct 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_cisco_nx_os_version.nasl");
  script_mandatory_keys("cisco_nx_os/version", "cisco_nx_os/model", "cisco_nx_os/device");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE ) ) exit( 0 );

if( ! device = get_kb_item( "cisco_nx_os/device" ) ) exit( 0 );
if( "Nexus" >!< device ) exit( 0 );

if ( ! nx_model = get_kb_item( "cisco_nx_os/model" ) ) exit( 0 );

if( nx_model =~ "^7[0-9]+" )
{
  affected = make_list(
			"4.1.(2)",
			"4.1.(3)",
			"4.1.(4)",
			"4.1.(5)",
			"4.2(3)",
			"4.2(4)",
			"4.2(6)",
			"4.2(8)",
			"4.2.(2a)",
			"5.0(2a)",
			"5.0(3)",
			"5.0(5)",
			"5.1(1)",
			"5.1(1a)",
			"5.1(3)",
			"5.1(4)",
			"5.1(5)",
			"5.1(6)",
			"5.2(1)",
			"5.2(3a)",
			"5.2(4)",
			"5.2(5)",
			"5.2(7)",
			"5.2(9)",
			"6.0(1)",
			"6.0(2)",
			"6.0(3)",
			"6.0(4)",
			"6.1(1)",
			"6.1(2)",
			"6.1(3)",
			"6.1(4)",
			"6.1(4a)",
			"6.1(5)",
			"6.2(10)",
			"6.2(12)",
			"6.2(14)S1",
			"6.2(2)",
			"6.2(2a)",
			"6.2(6)",
			"6.2(6b)",
			"6.2(8)",
			"6.2(8a)",
			"6.2(8b)",
			"7.2(0)N1(0.1)"
		);
}


foreach af ( affected )
{
  if( version == af )
  {
    report = report_fixed_ver(  installed_version:version, fixed_version: "7.2(2)D1(1)" );
    security_message( port:0, data:report );
    exit( 0 );
  }
}

exit( 99 );

