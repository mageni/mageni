###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_orion_npm_mult_xss_vuln.nasl 13766 2019-02-19 15:28:10Z cfischer $
#
# SolarWinds Orion NPM Multiple Cross Site Scripting Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:solarwinds:orion_network_performance_monitor";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801986");
  script_version("$Revision: 13766 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-19 16:28:10 +0100 (Tue, 19 Feb 2019) $");
  script_tag(name:"creation_date", value:"2011-09-20 15:38:54 +0200 (Tue, 20 Sep 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SolarWinds Orion NPM Multiple Cross Site Scripting Vulnerabilities");

  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2011/Sep/107");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/105020/orionsolarwinds-xss.txt");
  script_xref(name:"URL", value:"http://www.derkeiler.com/Mailing-Lists/Full-Disclosure/2011-09/msg00144.html");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_solarwinds_orion_npm_consolidation.nasl");
  script_mandatory_keys("solarwinds/orion/npm/detected");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary
  HTML and script code in a user's browser session in the context of a vulnerable
  site. This may allow an attacker to steal cookie-based authentications and launch further attacks.");

  script_tag(name:"affected", value:"SolarWinds Orion Network Performance Monitor (NPM) 10.1.2 SP1");

  script_tag(name:"insight", value:"The flaws are due to an input validation error in
  NetPerfMon/CustomChart.aspx and NetPerfMon/MapView.aspx pages when processing the 'Title' parameter.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the
  disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade
  to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"This host is running SolarWinds Orion NPM and is prone to cross
  site scripting vulnerabilities.");

  script_tag(name:"solution_type", value:"WillNotFix");

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

if (version_is_equal(version: version, test_version: "10.1.2.SP1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "None", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);