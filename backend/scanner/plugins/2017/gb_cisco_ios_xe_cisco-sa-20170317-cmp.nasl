###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_ios_xe_cisco-sa-20170317-cmp.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# Cisco IOS XE Software Cluster Management Protocol Remote Code Execution Vulnerability
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

CPE = "cpe:/o:cisco:ios_xe";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106671");
  script_cve_id("CVE-2017-3881");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_version("$Revision: 12106 $");

  script_name("Cisco IOS XE Software Cluster Management Protocol Remote Code Execution Vulnerability");

  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170317-cmp");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"summary", value:"A vulnerability in the Cisco Cluster Management Protocol (CMP) processing
code in Cisco IOS XE Software could allow an unauthenticated, remote attacker to cause a reload of an
affected device or remotely execute code with elevated privileges.");

  script_tag(name:"insight", value:"The Cluster Management Protocol utilizes Telnet internally as a signaling
and command protocol between cluster members. The vulnerability is due to the combination of two factors:

  - The failure to restrict the use of CMP-specific Telnet options only to internal, local communications between
cluster members and instead accept and process such options over any Telnet connection to an affected device, and

  - The incorrect processing of malformed CMP-specific Telnet options.

An attacker could exploit this vulnerability by sending malformed CMP-specific Telnet options while establishing
a Telnet session with an affected Cisco device configured to accept Telnet connections.");

  script_tag(name:"impact", value:"An exploit could allow an attacker to execute arbitrary code and obtain full
control of the device or cause a reload of the affected device.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-03-20 11:02:32 +0700 (Mon, 20 Mar 2017)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("gb_cisco_ios_xe_version.nasl");
  script_mandatory_keys("cisco_ios_xe/version");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE))
  exit(0);

affected = make_list(
		'2.2.0',
		'2.2.1',
		'2.2.2',
		'2.2.3',
		'2.3.0',
		'2.3.1',
		'2.3.1t',
		'2.3.2',
		'2.4.0',
		'2.4.1',
		'2.4.2',
		'2.4.3',
		'2.5.0',
		'2.5.1',
		'2.6.0',
		'2.6.1',
		'3.1.0SG',
		'3.1.1SG',
		'3.2.0SG',
		'3.2.0XO',
		'3.2.10SG',
		'3.2.11SG',
		'3.2.1SG',
		'3.2.2SG',
		'3.2.3SG',
		'3.2.4SG',
		'3.2.5SG',
		'3.2.6SG',
		'3.2.7SG',
		'3.2.8SG',
		'3.2.9SG',
		'3.3.0SG',
		'3.3.0SQ',
		'3.3.0XO',
		'3.3.1SG',
		'3.3.1SQ',
		'3.3.1XO',
		'3.3.2SG',
		'3.3.2XO',
		'3.4.0SG',
		'3.4.0SQ',
		'3.4.1SG',
		'3.4.1SQ',
		'3.4.2SG',
		'3.4.3SG',
		'3.4.4SG',
		'3.4.5SG',
		'3.4.6SG',
		'3.4.7SG',
		'3.4.7aSG',
		'3.4.8SG',
		'3.4.9SG',
		'3.5.0E',
		'3.5.0SQ',
		'3.5.1E',
		'3.5.1SQ',
		'3.5.2E',
		'3.5.2SQ',
		'3.5.3E',
		'3.5.3SQ',
		'3.5.4SQ',
		'3.5.5SQ',
		'3.5.7SQ',
		'3.6.0E',
		'3.6.1E',
		'3.6.2E',
		'3.6.2aE',
		'3.6.3E',
		'3.6.4E',
		'3.6.5E',
		'3.6.5aE',
		'3.6.5bE',
		'3.6.6E',
		'3.7.0E',
		'3.7.1E',
		'3.7.2E',
		'3.7.3E',
		'3.7.4E',
		'3.7.5E',
		'3.8.0E',
		'3.8.0EX',
		'3.8.1E',
		'3.8.1S',
		'3.8.2E',
		'3.8.3E',
		'3.9.0E',
		'3.9.1E');

foreach af (affected) {
  if (version == af) {
    report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);

