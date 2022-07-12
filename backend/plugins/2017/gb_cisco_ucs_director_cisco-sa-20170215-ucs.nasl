###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_ucs_director_cisco-sa-20170215-ucs.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# Cisco UCS Director Privilege Escalation Vulnerability
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

CPE = "cpe:/a:cisco:ucs_director";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106604");
  script_cve_id("CVE-2017-3801");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_version("$Revision: 12106 $");

  script_name("Cisco UCS Director Privilege Escalation Vulnerability");

  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170215-ucs");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"Update to version 6.0.1.0.");

  script_tag(name:"summary", value:"A vulnerability in the web-based GUI of Cisco UCS Director could allow an
authenticated, local attacker to execute arbitrary workflow items with just an end-user profile.");

  script_tag(name:"insight", value:"The vulnerability is due to improper role-based access control (RBAC) after
the Developer Menu is enabled in Cisco UCS Director. An attacker could exploit this vulnerability by enabling
Developer Mode for his/her user profile with an end-user profile and then adding new catalogs with arbitrary
workflow items to his/her profile.");

  script_tag(name:"impact", value:"An exploit could allow an attacker to perform any actions defined by these
workflow items, including actions affecting other tenants.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-02-16 15:15:33 +0700 (Thu, 16 Feb 2017)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("gb_cisco_ucs_director_version.nasl");
  script_mandatory_keys("cisco_ucs_director/version");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe:CPE))
  exit(0);

affected = make_list(
		'6.0.0.0',
		'6.0.0.1');

foreach af (affected) {
  if (version == af) {
    report = report_fixed_ver(installed_version: version, fixed_version: "6.0.1.0");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);

