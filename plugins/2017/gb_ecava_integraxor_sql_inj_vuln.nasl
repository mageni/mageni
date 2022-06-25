###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ecava_integraxor_sql_inj_vuln.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# ECAVA IntegraXor SQL Injection Vulnerability
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

CPE = "cpe:/a:ecava:integraxor";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106607");
  script_version("$Revision: 12106 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-02-17 10:06:51 +0700 (Fri, 17 Feb 2017)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2016-8341");
  script_bugtraq_id(95907);

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("ECAVA IntegraXor Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_ecava_integraxor_detect.nasl");
  script_mandatory_keys("EcavaIntegraXor/Installed");

  script_tag(name:"summary", value:"ECAVA IntegraXor is prone to multiple SQL injection vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The Ecava IntegraXor web server has parameters that are vulnerable to SQL
injection. If the queries are not sanitized, the host's database could be subject to read, write, and delete
commands.");

  script_tag(name:"impact", value:"A successful exploit of this vulnerability could lead to arbitrary data
leakage, data manipulation, and remote code execution.");

  script_tag(name:"affected", value:"Version 5.0.413.0");

  script_tag(name:"solution", value:"Update to 5.2.722.2 or later versions.");

  script_xref(name:"URL", value:"https://ics-cert.us-cert.gov/advisories/ICSA-17-031-02");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version == "5.0.413.0") {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.2.722.2");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
