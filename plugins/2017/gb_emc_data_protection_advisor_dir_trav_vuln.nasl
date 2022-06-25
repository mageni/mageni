##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_emc_data_protection_advisor_dir_trav_vuln.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# EMC Data Protection Advisor Directory Traversal Vulnerability
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

CPE = "cpe:/a:emc:data_protection_advisor";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106549");
  script_version("$Revision: 12106 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-01-30 10:52:02 +0700 (Mon, 30 Jan 2017)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2016-8211");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("EMC Data Protection Advisor Directory Traversal Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_emc_data_protection_advisor_detect.nasl");
  script_mandatory_keys("emc_data_protection_advisor/installed");

  script_tag(name:"summary", value:"EMC Data Protection Advisor is prone to a directory traversal
vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"EMC Data Protection Advisor is affected by a path traversal vulnerability.
Attackers may potentially exploit this vulnerability to access unauthorized information by supplying specially
crafted strings in input parameters of the application.");

  script_tag(name:"affected", value:"EMC Data Protection Advisor 6.1.x, 6.2, 6.2.1, 6.2.2 and 6.2.3 before
patch 446.");

  script_tag(name:"solution", value:"Update to 6.2.3 patch 446 or later versions.");

  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2017/Jan/87");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "6.2.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.2.3 patch 446");
  security_message(port: port, data: report);
  exit(0);
}

if (version == "6.2.3") {
  build = get_kb_item("emc_data_protection_advisor/build");
  if (!build || version_is_less(version: build, test_version: "446")) {
    report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "6.2.3",
                              fixed_build: "446");
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(0);
