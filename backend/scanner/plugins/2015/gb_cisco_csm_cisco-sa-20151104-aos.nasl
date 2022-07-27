###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_csm_cisco-sa-20151104-aos.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# Cisco Content Security Management Appliance AsyncOS TCP Flood Denial of Service Vulnerability
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

CPE = "cpe:/h:cisco:content_security_management_appliance";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105436");
  script_cve_id("CVE-2015-6321");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_version("$Revision: 12106 $");

  script_name("Cisco Content Security Management Appliance AsyncOS TCP Flood Denial of Service Vulnerability");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20151104-aos");
  script_xref(name:"URL", value:"https://tools.cisco.com/bugsearch/bug/CSCus79777");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The vulnerability is due to improper handling of TCP packets sent at a high rate. An attacker could exploit this vulnerability by sending crafted TCP packets to the affected system.");
  script_tag(name:"solution", value:"See Vendor advisory.");
  script_tag(name:"summary", value:"A vulnerability in the network stack of Cisco AsyncOS for Cisco Content Security Management Appliance (SMA) could allow an
unauthenticated, remote attacker to exhaust all available memory, preventing the affected device from accepting new TCP connections.");

  script_tag(name:"affected", value:"See Vendor advisory.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-11-06 15:21:08 +0100 (Fri, 06 Nov 2015)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("gb_cisco_csma_version.nasl");
  script_mandatory_keys("cisco_csm/version");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE ) ) exit( 0 );

version = str_replace( string:version, find:"-", replace:"." );

if( version_is_less( version:version, test_version:'9.1.0.032' ) ) fix = '9.1.0-032';
if( version_in_range( version:version, test_version:'9.1.1', test_version2:'9.1.1.004' ) ) fix = '9.1.1-005';
if( version_in_range( version:version, test_version:'9.5.0', test_version2:'9.5.0.024' ) ) fix = '9.5.0-025';

if( fix )
{
  report = 'Installed version: ' + version + '\n' +
           'Fixed version:     ' + fix + '\n';

  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );

