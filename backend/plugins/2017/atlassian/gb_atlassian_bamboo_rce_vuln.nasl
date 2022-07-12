###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_atlassian_bamboo_rce_vuln.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# Atlassian Bamboo Remote Command Execution Vulnerability
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

CPE = "cpe:/a:atlassian:bamboo";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140602");
  script_version("$Revision: 12106 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-12-14 11:59:48 +0700 (Thu, 14 Dec 2017)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_cve_id("CVE-2017-9514");
  script_bugtraq_id(101269);

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Atlassian Bamboo Remote Command Execution Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_atlassian_bamboo_detect.nasl");
  script_mandatory_keys("AtlassianBamboo/Installed");

  script_tag(name:"summary", value:"Atlassian Bamboo is prone to a remote code execution vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Bamboo has a REST endpoint that parsed a YAML file and did not sufficiently
restrict which classes could be loaded. An attacker who can log in to Bamboo as a user is able to exploit this
vulnerability to execute Java code of their choice on systems that have a vulnerable version of Bamboo.");

  script_tag(name:"affected", value:"Atlassiona Bamboo version 6.0.x, 6.1.x and 6.2.0.");

  script_tag(name:"solution", value:"Update to 6.0.5, 6.1.4, 6.2.1 or later.");

  script_xref(name:"URL", value:"https://confluence.atlassian.com/bamboo/bamboo-security-advisory-2017-10-11-938843921.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range(version: version, test_version: "6.0.0", test_version2: "6.0.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.0.5");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "6.1.0", test_version2: "6.1.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.1.4");
  security_message(port: port, data: report);
  exit(0);
}

if (version == "6.2.0") {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.2.1");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
