##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hp_network_automation_hpsbgn03677.nasl 12096 2018-10-25 12:26:02Z asteins $
#
# HP Network Automation RCE Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
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

CPE = 'cpe:/a:hp:network_automation';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106430");
  script_version("$Revision: 12096 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-25 14:26:02 +0200 (Thu, 25 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-12-01 11:55:23 +0700 (Thu, 01 Dec 2016)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2016-8511");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("HP Network Automation RCE Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_hp_network_automation_detect.nasl");
  script_mandatory_keys("hp/network_automation/installed");

  script_tag(name:"summary", value:"HP Network Automation is prone to a remote code execution vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Potential security vulnerabilities in RPCServlet and Java deserialization
were addressed by HPE Network Automation. The vulnerabilities could be remotely exploited to allow code
execution.");

  script_tag(name:"impact", value:"An attacker may execute arbitrary code.");

  script_tag(name:"affected", value:"HP Network Automation Software v9.1x, v9.2x, v10.00, v10.00.01, v10.00.02,
v10.10, v10.11, v10.11.01, v10.20.");

  script_tag(name:"solution", value:"Install the provided patches.");

  script_xref(name:"URL", value:"https://h20564.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-c05344849");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less_equal(version: version, test_version: "10.00")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.00.021");
  security_message(port: port, data: report);
  exit(0);
}

if (version == "10.10") {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.11");
  security_message(port: port, data: report);
  exit(0);
}

if (version == "10.11") {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.11.011");
  security_message(port: port, data: report);
  exit(0);
}

if (version == "10.20") {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.20.001");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
