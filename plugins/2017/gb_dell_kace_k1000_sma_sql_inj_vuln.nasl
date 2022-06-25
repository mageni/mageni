##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dell_kace_k1000_sma_sql_inj_vuln.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# Dell KACE Systems Management Appliance SQL Injection Vulnerability
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

CPE = 'cpe:/a:quest:kace_systems_management_appliance';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140288");
  script_version("$Revision: 12106 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-08-09 12:28:27 +0700 (Wed, 09 Aug 2017)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2017-12567");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Dell KACE Systems Management Appliance SQL Injection Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_quest_kace_sma_detect.nasl");
  script_mandatory_keys("quest_kace_sma/detected", "quest_kace_sma/model");

  script_tag(name:"summary", value:"An SQL injection exists in Dell/Quest KACE Asset Management Appliance.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"KACE Asset Management Appliance version 6.4.120822 until 7.2.101.");

  script_tag(name:"solution", value:"Update to the latest version.");

  script_xref(name:"URL", value:"https://support.quest.com/kace-systems-management-appliance/kb/231874");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

model = get_kb_item("quest_kace_sma/model");
if (model !~ "^(k|K)1000")
  exit(0);

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range(version: version, test_version: "6.4.120822", test_version2: "7.2.101")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
