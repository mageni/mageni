###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_prestashop_rce_vuln.nasl 13115 2019-01-17 09:41:25Z ckuersteiner $
#
# PrestaShop < 1.7.2.5 RCE Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2019 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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

CPE = 'cpe:/a:prestashop:prestashop';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141886");
  script_version("$Revision: 13115 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-17 10:41:25 +0100 (Thu, 17 Jan 2019) $");
  script_tag(name:"creation_date", value:"2019-01-17 15:39:38 +0700 (Thu, 17 Jan 2019)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_cve_id("CVE-2018-20717");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PrestaShop < 1.7.2.5 RCE Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_prestashop_detect.nasl");
  script_mandatory_keys("prestashop/installed");

  script_tag(name:"summary", value:"In the orders section of PrestaShop, an attack is possible after gaining
access to a target store with a user role with the rights of at least a Salesman or higher privileges. The
attacker can then inject arbitrary PHP objects into the process and abuse an object chain in order to gain Remote
Code Execution.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"PrestaShop version 1.7.2.4 and prior.");

  script_tag(name:"solution", value:"Update to version 1.7.2.5 or later.");

  script_xref(name:"URL", value:"https://build.prestashop.com/news/prestashop-1-7-2-5-maintenance-release/");
  script_xref(name:"URL", value:"https://blog.ripstech.com/2018/prestashop-remote-code-execution/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "1.7.2.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.7.2.5");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
