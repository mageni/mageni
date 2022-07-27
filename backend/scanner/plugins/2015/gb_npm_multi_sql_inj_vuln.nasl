###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_npm_multi_sql_inj_vuln.nasl 13766 2019-02-19 15:28:10Z cfischer $
#
# SolarWinds Network Performance Monitor Multiple SQL Injection Vulnerabilities
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2015 Greenbone Networks GmbH
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

CPE = 'cpe:/a:solarwinds:orion_network_performance_monitor';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105966");
  script_version("$Revision: 13766 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-19 16:28:10 +0100 (Tue, 19 Feb 2019) $");
  script_tag(name:"creation_date", value:"2015-03-06 12:47:16 +0700 (Fri, 06 Mar 2015)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2014-9566");

  script_name("SolarWinds Network Performance Monitor Multiple SQL Injection Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_solarwinds_orion_npm_consolidation.nasl");
  script_mandatory_keys("solarwinds/orion/npm/detected");

  script_tag(name:"summary", value:"SolarWinds Network Performance Monitor is prone to multiple
  SQL Injection vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"On both the GetAccounts and GetAccountGroups endpoints, the
  'sort' and 'dir' parameters are susceptible to boolean-/time-based, and stacked injections. The attacker
  has to be authenticated but it can be even exploited under a guest account.");

  script_tag(name:"impact", value:"An authenticated attacker might execute arbitrary SQL commands
  to compromise the application, access or modify data, or exploit latent vulnerabilities in the
  underlying database.");

  script_tag(name:"affected", value:"SolarWinds NPM 11.4 and previous.");

  script_tag(name:"solution", value:"Upgrade to SolarWinds NPM 11.5 or later.");

  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2015/Mar/18");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos['version'];
location = infos['location'];

if (version_is_less(version: version, test_version: "11.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "11.5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);