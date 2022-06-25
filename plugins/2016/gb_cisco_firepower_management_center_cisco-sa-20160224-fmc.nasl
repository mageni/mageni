###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_firepower_management_center_cisco-sa-20160224-fmc.nasl 12313 2018-11-12 08:53:51Z asteins $
#
# Cisco FirePOWER Management Center Unauthenticated Information Disclosure Vulnerability
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

CPE = "cpe:/a:cisco:firepower_management_center";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105583");
  script_cve_id("CVE-2015-6411");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_version("$Revision: 12313 $");

  script_name("Cisco FirePOWER Management Center Unauthenticated Information Disclosure Vulnerability");

  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160224-fmc");

  script_tag(name:"impact", value:"An attacker could exploit this vulnerability by reading the information disclosed in the help files to conduct further attacks.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability is due to verbose output returned when HTML files are retrieved from the affected system.");

  script_tag(name:"solution", value:"See vendor advisory");
  script_tag(name:"summary", value:"A vulnerability in the Cisco FirePOWER Management Center could allow an unauthenticated, remote attacker to obtain information about the Cisco FirePOWER Management Center software version from the device login page.");
  script_tag(name:"affected", value:"Cisco FirePOWER Management Center 5.3 through 6.0.0.1");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"last_modification", value:"$Date: 2018-11-12 09:53:51 +0100 (Mon, 12 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-03-21 14:00:27 +0100 (Mon, 21 Mar 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_cisco_firepower_management_center_version.nasl");
  script_mandatory_keys("cisco_firepower_management_center/version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE ) ) exit( 0 );

affected = make_list( "5.4.1.3", "5.4.1.5", "5.4.1.4", "5.4.1.2",
                      "5.4.1.1", "5.4.1",   "5.4.1.0", "5.4.0",
                      "5.4.0.0", "6.0.0",   "6.0.0.0", "6.0.0.1",
                      "5.3.0.3", "5.3.1.3", "5.3.1.4", "5.3.1.5",
                      "5.3.1.6", "5.3.1",   "5.3.1.0" );

foreach af ( affected )
{
  if( version == af  )
  {
    report = report_fixed_ver( installed_version:version, fixed_version:"See vendor advisory");
    security_message( port:0, data:report );
    exit( 0 );
  }
}

exit( 99 );

