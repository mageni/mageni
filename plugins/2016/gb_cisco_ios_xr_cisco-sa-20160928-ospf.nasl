###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_ios_xr_cisco-sa-20160928-ospf.nasl 12363 2018-11-15 09:51:15Z asteins $
#
# Cisco IOS XR Software Open Shortest Path First Link State Advertisement Denial of Service Vulnerability
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

CPE = "cpe:/o:cisco:ios_xr";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106313");
  script_cve_id("CVE-2016-6421");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_version("$Revision: 12363 $");

  script_name("Cisco IOS XR Software Open Shortest Path First Link State Advertisement Denial of Service Vulnerability");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160928-ospf");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"Upgrade to 5.3.4.13i or 6.1.2.3i or
 6.1.22.9i or 6.2.1.11i or later.");

  script_tag(name:"summary", value:"A vulnerability in the implementation of Open Shortest Path First (OSPF)
Link State Advertisement (LSA) functionality in Cisco IOS XR Software could allow an unauthenticated, remote
attacker to cause a denial of service (DoS) condition.");

  script_tag(name:"insight", value:"The vulnerability is due to a memory error in OSPF. An attacker could
exploit this vulnerability by sending a crafted OSPF LSA update to an affected device.");

  script_tag(name:"impact", value:"A successful exploit could allow the attacker to cause the OSPF process
to restart when the crafted OSPF LSA update is received, resulting in a DoS condition.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"$Date: 2018-11-15 10:51:15 +0100 (Thu, 15 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-09-29 15:35:38 +0700 (Thu, 29 Sep 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_cisco_ios_xr_version.nasl");
  script_mandatory_keys("cisco/ios_xr/version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE ) ) exit( 0 );

if( version == "5.2.2" )
{
  report = report_fixed_ver(  installed_version:version, fixed_version: "5.3.4.13i or later" );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );

