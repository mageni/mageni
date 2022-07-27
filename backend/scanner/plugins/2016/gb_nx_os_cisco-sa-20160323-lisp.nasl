###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_nx_os_cisco-sa-20160323-lisp.nasl 14181 2019-03-14 12:59:41Z cfischer $
#
# Cisco NX-OS Software Locator/ID Separation Protocol Packet Denial of Service Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
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

CPE = 'cpe:/o:cisco:nx-os';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105644");
  script_cve_id("CVE-2016-1351");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_version("$Revision: 14181 $");

  script_name("Cisco NX-OS Software Locator/ID Separation Protocol Packet Denial of Service Vulnerability");

  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160323-lisp");
  script_tag(name:"last_modification", value:"$Date: 2019-03-14 13:59:41 +0100 (Thu, 14 Mar 2019) $");
  script_tag(name:"creation_date", value:"2016-05-04 14:06:24 +0200 (Wed, 04 May 2016)");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_cisco_nx_os_version.nasl");
  script_mandatory_keys("cisco_nx_os/version", "cisco_nx_os/model", "cisco_nx_os/device");

  script_tag(name:"impact", value:"An attacker could exploit this vulnerability by sending a malformed LISP packet on UDP port 4341.
  An exploit could allow the attacker to cause a denial of service (DoS) condition.");
  script_tag(name:"vuldetect", value:"Check the NX OS version.");
  script_tag(name:"insight", value:"The vulnerability is due to a lack of proper input validation when a malformed LISP packet header is received.");
  script_tag(name:"solution", value:"See the vendor advisory for a solution");
  script_tag(name:"summary", value:"A vulnerability in the Locator/ID Separation Protocol (LISP) of Cisco NX-OS Software running on the Cisco Nexus 7000
  and Nexus 7700 Series Switches with an M1 Series Gigabit Ethernet Module could allow an unauthenticated, remote attacker to cause a reload of the vulnerable device.");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! device = get_kb_item( "cisco_nx_os/device" ) ) exit( 0 );
if( "Nexus" >!< device ) exit( 0 );

if( ! nx_model = get_kb_item( "cisco_nx_os/model" ) )   exit( 0 );
if( nx_model !~ "^7") exit(0);

if( ! nx_ver = get_kb_item( "cisco_nx_os/version" ) ) exit( 0 );

affected = make_list("4.1.(2)",
                     "4.1.(3)",
                     "4.1.(4)",
                     "4.1.(5)",
                     "4.2.(2a)",
                     "4.2(3)",
                     "4.2(4)",
                     "4.2(6)",
                     "4.2(8)",
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
                     "6.2(2)",
                     "6.2(2a)",
                     "6.2(6)",
                     "6.2(6b)",
                     "6.2(8)",
                     "6.2(8a)",
                     "6.2(8b)",
                     "6.2(10)",
                     "6.2(12)",
                     "6.2(14)S1",
                     "7.2(0)N1(0.1)");

foreach af ( affected )
{
  if( nx_ver == af )
  {
    report = report_fixed_ver(  installed_version:nx_ver, fixed_version:"See advisory" );
    security_message( port:0, data:report );
    exit( 0 );
  }
}

exit( 99 );