###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_prime_dcnm_cisco-sa-20170607-dcnm1.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# Cisco Prime Data Center Network Manager Debug Remote Code Execution Vulnerability
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

CPE = "cpe:/a:cisco:prime_data_center_network_manager";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106851");
  script_cve_id("CVE-2017-6639");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_version("$Revision: 12106 $");

  script_name("Cisco Prime Data Center Network Manager Debug Remote Code Execution Vulnerability");

  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170607-dcnm1");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"Update to Cisco Prime DCNM Software releases 10.2(1) or later.");

  script_tag(name:"summary", value:"A vulnerability in the role-based access control (RBAC) functionality of
Cisco Prime Data Center Network Manager (DCNM) could allow an unauthenticated, remote attacker to access
sensitive information or execute arbitrary code with root privileges on an affected system.");

  script_tag(name:"insight", value:"The vulnerability is due to the lack of authentication and authorization
mechanisms for a debugging tool that was inadvertently enabled in the affected software. An attacker could
exploit this vulnerability by remotely connecting to the debugging tool via TCP.");

  script_tag(name:"impact", value:"A successful exploit could allow the attacker to access sensitive information
about the affected software or execute arbitrary code with root privileges on the affected system.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-06-08 10:09:07 +0700 (Thu, 08 Jun 2017)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("gb_cisco_prime_data_center_network_manager_detect.nasl");
  script_mandatory_keys("cisco_prime_dcnm/installed");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE))
  exit(0);

affected = make_list('10.1.0',
                     '10.1(1)',
                     '10.1(2)');

foreach af (affected) {
  if (version == af) {
    report = report_fixed_ver(installed_version: version, fixed_version: "10.2(1)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
