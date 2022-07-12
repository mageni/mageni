# Copyright (C) 2016 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

CPE = "cpe:/a:apache:struts";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808537");
  script_version("2021-03-30T14:13:04+0000");
  script_cve_id("CVE-2016-4465");
  script_bugtraq_id(91278);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2021-03-31 10:16:54 +0000 (Wed, 31 Mar 2021)");
  script_tag(name:"creation_date", value:"2016-11-18 14:36:30 +0530 (Fri, 18 Nov 2016)");
  script_name("Apache Struts DoS Vulnerability (S2-041)");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_dependencies("gb_apache_struts_consolidation.nasl");
  script_mandatory_keys("apache/struts/detected");

  script_xref(name:"URL", value:"https://cwiki.apache.org/confluence/display/WW/S2-041");

  script_tag(name:"summary", value:"Apache Struts is prone to a Denial of Service (DoS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the
  target host.");

  script_tag(name:"insight", value:"If an application allows enter an URL field in a form
  and built-in URLValidator is used, it is possible to prepare a special URL which will be
  used to overload server process when performing validation of the URL.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to
  cause a DoS.");

  script_tag(name:"affected", value:"Apache Struts 2.3.20 through 2.3.28.1 and 2.5 through
  2.5.12.");

  script_tag(name:"solution", value:"Update to version 2.3.29, 2.5.13 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

vers = infos["version"];

if (version_in_range(version: vers, test_version: "2.5.0", test_version2: "2.5.12")) {
  fix = "2.5.13";
  VULN = TRUE;
}

else if (version_in_range(version: vers, test_version: "2.3.20", test_version2: "2.3.28.1")) {
  fix = "2.3.29";
  VULN = TRUE;
}

if (VULN) {
  report = report_fixed_ver(installed_version: vers, fixed_version: fix, install_path: infos["location"]);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);