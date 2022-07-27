###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_ios_xr_cisco-sa-20160104-iosxr.nasl 11961 2018-10-18 10:49:40Z asteins $
#
# Cisco IOS XR Software OSPF Link State Advertisement PCE Vulnerability
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

CPE = "cpe:/o:cisco:ios_xr";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105529");
  script_cve_id("CVE-2015-6432");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_version("$Revision: 11961 $");
  script_tag(name:"qod_type", value:"package");

  script_name("Cisco IOS XR Software OSPF Link State Advertisement PCE Vulnerability");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160104-iosxr");

  script_tag(name:"impact", value:"A successful exploit could allow the attacker to cause a DoS condition due to the OSPF process restarting when the crafted OSPF LSA update is received.");
  script_tag(name:"vuldetect", value:"Check the IOS XR Version");
  script_tag(name:"insight", value:"The vulnerability is due to the number of OSPF Path Computation Elements (PCEs) that are configured for an OSPF LSA opaque area update. An attacker could exploit this vulnerability by sending a crafted OSPF LSA update to an affected device that is running the vulnerable software and OSPF configuration.");
  script_tag(name:"solution", value:"Cisco has released software updates that address this vulnerability.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"A vulnerability in Open Shortest Path First (OSPF) Link State Advertisement (LSA) handling by Cisco IOS XR Software could allow an unauthenticated, remote attacker to cause a denial of service (DoS) condition.");
  script_tag(name:"affected", value:"Cisco IOS XR Software Releases 4.1.1, 4.2.0, 4.2.3, 4.3.0, 4.3.2, 5.0.0, 5.1.0, 5.2.0, 5.2.2, 5.2.4, 5.3.0, and 5.3.2 are vulnerable.");

  script_tag(name:"last_modification", value:"$Date: 2018-10-18 12:49:40 +0200 (Thu, 18 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-01-26 15:02:08 +0100 (Tue, 26 Jan 2016)");
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

affected = make_list( "4.1.1", "4.2.0", "4.2.3", "4.3.0", "4.3.2", "5.0.0", "5.1.0", "5.2.0", "5.2.2", "5.2.4", "5.3.0", "5.3.2" );

foreach af ( affected )
{
  if( version == af )
  {
    report = report_fixed_ver(  installed_version:version, fixed_version:'See vendor advisory' );
    security_message( port:0, data:report );
    exit( 0 );
  }
}

exit( 99 );

