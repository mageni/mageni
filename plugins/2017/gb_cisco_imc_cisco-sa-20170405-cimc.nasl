###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_imc_cisco-sa-20170405-cimc.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# Cisco Integrated Management Controller Redirection Vulnerability
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

CPE = "cpe:/a:cisco:integrated_management_controller";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106720");
  script_cve_id("CVE-2017-6604");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_version("$Revision: 12106 $");

  script_name("Cisco Integrated Management Controller Redirection Vulnerability");

  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170405-cimc");

  script_tag(name:"summary", value:"A vulnerability in the web interface of Cisco Integrated Management
Controller (IMC) Software could allow an unauthenticated, remote attacker to redirect a user to a malicious web
page.");

  script_tag(name:"insight", value:"The vulnerability is due to improper input validation of parameters in
HTTP requests. An attacker could exploit this vulnerability by sending a crafted HTTP request to an affected
system, which could cause the web interface of the affected software to redirect the request to a malicious URL.");

  script_tag(name:"impact", value:"This vulnerability is known as an open redirect attack, which is used in
phishing attacks to get users to visit malicious sites without their knowledge.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See vendor advisory");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-04-07 10:17:03 +0200 (Fri, 07 Apr 2017)");

  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("gb_cisco_imc_detect.nasl");
  script_mandatory_keys("cisco_imc/installed");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe:CPE))
  exit(0);

affected = make_list(
		'2.2(8b)',
		'3.0(1c)',
		'3.1(2c)B');

foreach af (affected) {
  if (version == af) {
    report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);

