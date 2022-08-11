###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_ise_cisco-sa-20170802-ise.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# Cisco Identity Services Engine Authentication Bypass Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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

CPE = "cpe:/a:cisco:identity_services_engine";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140273");
  script_cve_id("CVE-2017-6747");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_version("$Revision: 12106 $");

  script_name("Cisco Identity Services Engine Authentication Bypass Vulnerability");

  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170802-ise");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"summary", value:"A vulnerability in the authentication module of Cisco Identity Services
Engine (ISE) could allow an unauthenticated, remote attacker to bypass local authentication.");

  script_tag(name:"insight", value:"The vulnerability is due to improper handling of authentication requests and
policy assignment for externally authenticated users. An attacker could exploit this vulnerability by
authenticating with a valid external user account that matches an internal username and incorrectly receiving the
authorization policy of the internal account.");

  script_tag(name:"impact", value:"An exploit could allow the attacker to have Super Admin privileges for the
ISE Admin portal.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-08-03 10:23:50 +0700 (Thu, 03 Aug 2017)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("gb_cisco_ise_version.nasl");
  script_mandatory_keys("cisco_ise/version");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE))
  exit(0);

affected = make_list(
		'1.3.0.722',
		'1.3.0.876',
		'1.3.0.909',
		'1.3.106.146',
		'1.3.120.135',
		'1.4.0.109',
		'1.4.0.181',
		'1.4.0.253',
		'1.4.0.908',
		'2.0.0.147',
		'2.0.0.169',
		'2.0.0.222',
		'2.0.1.130',
		'2.1.0.474',
		'2.1.0.800',
		'2.1.102.101');

foreach af (affected) {
  if (version == af) {
    report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);

