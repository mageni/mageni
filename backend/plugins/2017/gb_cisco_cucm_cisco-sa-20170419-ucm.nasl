###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_cucm_cisco-sa-20170419-ucm.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# Cisco Unified Communications Manager Denial of Service Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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

CPE = "cpe:/a:cisco:unified_communications_manager";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106780");
  script_cve_id("CVE-2017-3808");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_version("$Revision: 12106 $");

  script_name("Cisco Unified Communications Manager Denial of Service Vulnerability");

  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170419-ucm");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"summary", value:"A vulnerability in the Session Initiation Protocol (SIP) UDP throttling
process of Cisco Unified Communications Manager (Cisco Unified CM) could allow an unauthenticated, remote
attacker to cause a denial of service (DoS) condition on an affected device.");

  script_tag(name:"insight", value:"The vulnerability is due to insufficient rate limiting protection. An
attacker could exploit this vulnerability by sending the affected device a high rate of SIP messages.");

  script_tag(name:"impact", value:"An exploit could allow the attacker to cause the device to reload
unexpectedly. The device and services will restart automatically.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-04-20 16:25:38 +0200 (Thu, 20 Apr 2017)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("gb_cisco_cucm_version.nasl");
  script_mandatory_keys("cisco/cucm/version");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe:CPE))
  exit(0);

version = str_replace(string: version, find: "-", replace: ".");

affected = make_list(
		'10.0.1.10000.12',
		'10.5.0.98000.88',
		'10.5.1.98991.13',
		'10.5.1.99995.9',
		'10.5.2.10000.5',
		'10.5.2.12901.1',
		'10.5.2.13900.9',
		'10.5.3.10000.9',
		'11.0.0.98000.225',
		'11.0.1.10000.10',
		'11.5.0.98000.480',
		'11.5.0.98000.486',
		'11.5.0.99838.4',
		'11.5.1.10000.6',
		'11.5.1.11007.2',
		'11.5.1.12000.1',
		'11.5.1.2',
		'11.5.0');

foreach af (affected) {
  if (version == af) {
    report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);

