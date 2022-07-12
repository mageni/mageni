##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_nagiosxi_mult_vuln_nov18.nasl 12416 2018-11-19 13:04:44Z cfischer $
#
# Nagios XI < 5.5.7 Multiple Vulnerabilities
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH
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

CPE = "cpe:/a:nagios:nagiosxi";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141686");
  script_version("$Revision: 12416 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-19 14:04:44 +0100 (Mon, 19 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-11-15 09:20:47 +0700 (Thu, 15 Nov 2018)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2018-15708", "CVE-2018-15709", "CVE-2018-15710", "CVE-2018-15711", "CVE-2018-15712",
                "CVE-2018-15713", "CVE-2018-15714");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Nagios XI < 5.5.7 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_nagios_XI_detect.nasl");
  script_mandatory_keys("nagiosxi/installed");

  script_tag(name:"summary", value:"Nagios XI is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Nagios XI is prone to multiple vulnerabilities:

  - Unauthenticated RCE via Command Argument Injection (CVE-2018-15708)

  - Authenticated Command Injection (CVE-2018-15709)

  - Local Privilege Escalation via Command Injection (CVE-2018-15710)

  - Unauthorized API Key Regeneration (CVE-2018-15711)

  - Unauthenticated Persistent Cross-site Scripting (CVE-2018-15712)

  - Authenticated Persistent Cross-site Scripting (CVE-2018-15713)

  - Reflected Cross-site Scripting (CVE-2018-15714)");

  script_tag(name:"affected", value:"Nagios XI version 5.5.6 and prior.");

  script_tag(name:"solution", value:"Update to version 5.5.7 or later.");

  script_xref(name:"URL", value:"https://www.nagios.com/products/security/");
  script_xref(name:"URL", value:"https://www.nagios.com/downloads/nagios-xi/change-log/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "5.5.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.5.7");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
