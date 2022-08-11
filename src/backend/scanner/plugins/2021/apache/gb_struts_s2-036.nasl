# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.117289");
  script_version("2021-04-06T14:13:01+0000");
  script_cve_id("CVE-2016-4461");
  script_bugtraq_id(91277);
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2021-04-07 10:26:17 +0000 (Wed, 07 Apr 2021)");
  script_tag(name:"creation_date", value:"2021-04-06 11:46:55 +0000 (Tue, 06 Apr 2021)");
  script_name("Apache Struts RCE Vulnerability (S2-036)");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_dependencies("gb_apache_struts_consolidation.nasl");
  script_mandatory_keys("apache/struts/detected");

  script_xref(name:"URL", value:"https://cwiki.apache.org/confluence/display/WW/S2-036");
  script_xref(name:"Advisory-ID", value:"S2-036");

  script_tag(name:"summary", value:"Apache Struts is prone to a remote code execution
  (RCE) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the
  target host.");

  script_tag(name:"insight", value:"The same issue was reported in S2-029 but the proposed
  solutions were not fully proper. The Apache Struts frameworks when forced, performs
  double evaluation of attributes' values assigned to certain tags so it is possible to
  pass in a value that will be evaluated again when a tag's attributes will be rendered.");

  script_tag(name:"impact", value:"Successfully exploiting this issue may allow an
  attacker to execute arbitrary code in the context of the affected application.");

  script_tag(name:"affected", value:"Apache Struts 2.0.0 through 2.3.28.1.");

  script_tag(name:"solution", value:"Adding a proper validation of each value that's
  coming in and it's used in tag's attributes.

  Don't use forced evaluation of an attribute other than value using %{...} syntax unless
  really needed for a valid use-case. 

  By upgrading to Struts 2.3.29 or 2.5.1, possible malicious effects of forced double
  evaluation are limited.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range(version: version, test_version: "2.0.0", test_version2: "2.3.28.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.3.29 / 2.5.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);