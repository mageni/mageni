###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_ipics_cisco-sa-20161026-ipics.nasl 12338 2018-11-13 14:51:17Z asteins $
#
# Cisco IP Interoperability and Collaboration System Universal Media Services Unauthorized Access Vulnerability
#
# Authors:
# Tameem Eissa <tameem.eissa@greenbone.net>
#
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

CPE = "cpe:/a:cisco:ip_interoperability_and_collaboration_system";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107071");
  script_cve_id("CVE-2016-6397");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_version("$Revision: 12338 $");

  script_name("Cisco IP Interoperability and Collaboration System Universal Media Services Unauthorized Access Vulnerability");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20161026-ipics");


  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");
  script_tag(name:"summary", value:"A vulnerability in the interdevice communications interface of the Cisco IP Interoperability and
Collaboration System (IPICS) Universal Media Services (UMS) could allow an unauthenticated, remote
attacker to modify configuration parameters of the UMS and cause the system to become unavailable.

The vulnerability is due to insufficient authentication for the interdevice communications interface
access. An attacker could exploit this issue by accessing the interdevice communications interface
and making changes to the UMS configuration, causing the system to become unavailable.

Cisco has released software updates that address this vulnerability. There are no workarounds that
address this vulnerability.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"$Date: 2018-11-13 15:51:17 +0100 (Tue, 13 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-10-28 12:59:52 +0200 (Fri, 28 Oct 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_cisco_ipics_version.nasl");
  script_mandatory_keys("cisco/ipics/version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE ) ) exit( 0 );

affected = make_list(
                '4.8.(1)',
                '4.8.(2)',
                '4.9.(1)',
                '4.9.(2)',
                '4.10.(1)' );

foreach af ( affected )
{
  if( version == af )
  {
    report = report_fixed_ver(  installed_version:version, fixed_version: "See advisory" );
    security_message( port:0, data:report );
    exit( 0 );
  }
}

exit( 99 );

