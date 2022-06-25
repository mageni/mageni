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
  script_oid("1.3.6.1.4.1.25623.1.0.808080");
  script_version("2021-03-30T14:13:04+0000");
  script_cve_id("CVE-2016-3082");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2021-03-31 10:16:54 +0000 (Wed, 31 Mar 2021)");
  script_tag(name:"creation_date", value:"2016-06-09 16:55:12 +0530 (Thu, 09 Jun 2016)");
  script_name("Apache Struts Arbitrary Code Execution Vulnerability (S2-031)");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_apache_struts2_detection.nasl");
  script_mandatory_keys("ApacheStruts/installed");

  script_xref(name:"URL", value:"https://cwiki.apache.org/confluence/display/WW/S2-031");

  script_tag(name:"summary", value:"Apache Struts is prone to an arbitrary code execution
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the
  target host.");

  script_tag(name:"insight", value:"The flaw exists as XSLTResult allows for the location
  of a stylesheet being passed as a request parameter.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to
  execute arbitrary code.");

  script_tag(name:"affected", value:"Apache Struts 2.0.0 through 2.3.28 except 2.3.20.3
  and 2.3.24.3.");

  script_tag(name:"solution", value:"Update to version 2.3.20.3, 2.3.24.3, 2.3.28.1 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

vers = infos["version"];

# nb: Single versions not vulnerable according to the advisory.
if (version_is_equal(version: vers, test_version: "2.3.20.3") ||
    version_is_equal(version: vers, test_version: "2.3.24.3"))
  exit(99);

if (version_in_range(version: vers, test_version: "2.0.0", test_version2: "2.3.28")) {
  report = report_fixed_ver(installed_version: vers, fixed_version: "2.3.20.3, 2.3.24.3, 2.3.28.1", install_path: infos["location"]);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);