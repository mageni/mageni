###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_sg3xx_82103.nasl 12387 2018-11-16 14:06:23Z cfischer $
#
# Cisco Small Business SG300 Managed Switch Denial of Service Vulnerability
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

CPE = "cpe:/o:cisco:300_series_managed_switch_firmware";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105588");
  script_bugtraq_id(82103);
  script_cve_id("CVE-2016-1299");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_version("$Revision: 12387 $");

  script_name("Cisco Small Business SG300 Managed Switch Denial of Service Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/82103");
  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160127-sbms");
  script_xref(name:"URL", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCuw87174");

  script_tag(name:"impact", value:"An attacker can exploit this issue to cause denial-of-service conditions.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability is due to improper handling, processing, and termination of HTTPS connections.
  An attacker could exploit this vulnerability by sending crafted HTTPS requests to management-enabled interfaces of an affected system.");

  script_tag(name:"solution", value:"Update to version 1.4.5.2 or later. Please see the references for more information.");

  script_tag(name:"summary", value:"Cisco Small Business SG300 Managed Switch is prone to a remote denial-of-service vulnerability.");

  script_tag(name:"affected", value:"Cisco Small Business SG300 Managed Switch Release 1.4.1.x is vulnerable.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"last_modification", value:"$Date: 2018-11-16 15:06:23 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-03-24 15:41:40 +0100 (Thu, 24 Mar 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_cisco_sg3xx_snmp_detect.nasl");
  script_mandatory_keys("cisco/300_series_managed_switch/version");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE ) ) exit( 0 );

if( version_in_range( version:version, test_version:"1.4.1", test_version2:"1.4.1.03" ) )
{
  report = report_fixed_ver(  installed_version:version, fixed_version:"Ask the vendor" );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );