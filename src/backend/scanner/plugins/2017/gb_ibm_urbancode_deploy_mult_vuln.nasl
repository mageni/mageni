##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_urbancode_deploy_mult_vuln.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# IBM UrbanCode Deploy Multiple Vulnerabilities
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

CPE = 'cpe:/a:ibm:urbancode_deploy';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106563");
  script_version("$Revision: 12106 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-02-03 09:38:09 +0700 (Fri, 03 Feb 2017)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2016-2942", "CVE-2016-2941", "CVE-2016-0320", "CVE-2016-6068", "CVE-2016-8938",
"CVE-2016-9008");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("IBM UrbanCode Deploy Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_ibm_urbancode_deploy_detect.nasl");
  script_mandatory_keys("ibm_urbancode_deplay/installed");

  script_tag(name:"summary", value:"IBM UrbanCode Deploy is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"IBM UrbanCode Deploy is prone to multiple vulnerabilities:

  - Pre-processing and post-processing scripts can access the entire domain model of server or agent.
(CVE-2016-2942)

  - Property files on agent file system during plugin step execution contain secure info in plain text.
(CVE-2016-2941)

  - REST endpoints do not properly authorize, allowing users to modify data with insufficient permissions.
(CVE-2016-0320)

  - API and CLI getResource expose secured role properties. (CVE-2016-6068)

  - Remote code execution possible due to insecure REST endpoint. (CVE-2016-8938)

  - Agent Relay ActiveMQ Broker unauthenticated JMX interface can be accessed from remote hosts. (CVE-2016-9008 )");

  script_tag(name:"impact", value:"An unauthenticated attacker may execute arbitrary code.");

  script_tag(name:"affected", value:"IBM UrbanCode Deploy before version 6.0.1.15, 6.1.3.4 and 6.2.3.");

  script_tag(name:"solution", value:"Check the referenced advisories for the right version to upgrade.");

  script_xref(name:"URL", value:"https://www-01.ibm.com/support/docview.wss?uid=swg2C1000218");
  script_xref(name:"URL", value:"https://www-01.ibm.com/support/docview.wss?uid=swg2C1000220");
  script_xref(name:"URL", value:"https://www-01.ibm.com/support/docview.wss?uid=swg2C1000222");
  script_xref(name:"URL", value:"https://www-01.ibm.com/support/docview.wss?uid=swg2C1000229");
  script_xref(name:"URL", value:"https://www-01.ibm.com/support/docview.wss?uid=swg2C1000237");
  script_xref(name:"URL", value:"https://www-01.ibm.com/support/docview.wss?uid=swg2C1000238");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range(version: version, test_version: "6.0", test_version2: "6.0.1.14") ||
    version_in_range(version: version, test_version: "6.1", test_version2: "6.1.3.3") ||
    version_in_range(version: version, test_version: "6.2", test_version2: "6.2.2.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "Check vendor advisory.");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
