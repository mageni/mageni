##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_foreman_sql_inj_vuln.nasl 12116 2018-10-26 10:01:35Z mmartin $
#
# Foreman < 1.16.1 Multiple Vulnerabilities
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

CPE = "cpe:/a:theforeman:foreman";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140939");
  script_version("$Revision: 12116 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 12:01:35 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-04-03 16:45:09 +0700 (Tue, 03 Apr 2018)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");

  script_cve_id("CVE-2018-1097");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Foreman < 1.16.1 SQL Injection Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_foreman_detect.nasl");
  script_mandatory_keys("foreman/installed");

  script_tag(name:"summary", value:"Foreman is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Foreman is prone to multiple vulnerabilities:

  - One of the parameters passed when saving widget positions on the dashboard is not properly escaped leading to
possibility of SQL injection. Due to the nature of the query, exploitation is limited to possible information
disclosure and does not allow modifications to the database. The vulnerable endpoint is only available to
authenticated users.

  - Users with limited permissions for powering oVirt/RHV hosts on and off may discover the username and password
used to connect to the compute resource. (CVE-2018-1097)");

  script_tag(name:"affected", value:"Foreman version 1.9 and higher.");

  script_tag(name:"solution", value:"Update to version 1.16.1 or later.");

  script_xref(name:"URL", value:"https://projects.theforeman.org/issues/23028");
  script_xref(name:"URL", value:"https://projects.theforeman.org/issues/22546");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range(version: version, test_version: "1.9", test_version2: "1.16.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.16.1");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
