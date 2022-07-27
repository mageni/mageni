###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_cucm_cisco-sa-20170405-ucm.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# Cisco Unified Communications Manager SQL Injection Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.106724");
  script_cve_id("CVE-2017-3886");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_version("$Revision: 12106 $");

  script_name("Cisco Unified Communications Manager SQL Injection Vulnerability");

  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170405-ucm");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"summary", value:"A vulnerability in the Cisco Unified Communications Manager web interface
could allow an authenticated, remote attacker to impact the confidentiality of the system by executing arbitrary
SQL queries. The attacker must be authenticated as an administrative user to execute SQL database queries.");

  script_tag(name:"insight", value:"The vulnerability is due to a lack of input validation on HTTP requests that
contain user-supplied input. An attacker could exploit this vulnerability by sending crafted HTTP requests that
contain malicious SQL statements to the affected system.");

  script_tag(name:"impact", value:"An exploit could allow the attacker to determine the presence of certain
values in the database.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-04-07 10:52:53 +0200 (Fri, 07 Apr 2017)");
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
		'11.0.1.10000.10',
		'11.5.1.10000.6');

foreach af (affected) {
  if (version == af) {
    report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);

