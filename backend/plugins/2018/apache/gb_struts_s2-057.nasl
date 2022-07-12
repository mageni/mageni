# Copyright (C) 2018 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.813786");
  script_version("2021-04-01T07:54:37+0000");
  script_cve_id("CVE-2018-11776");
  script_bugtraq_id(105125);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2021-04-01 10:13:05 +0000 (Thu, 01 Apr 2021)");
  script_tag(name:"creation_date", value:"2018-08-23 12:45:43 +0530 (Thu, 23 Aug 2018)");
  script_name("Apache Struts RCE Vulnerability (S2-057)");
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_apache_struts_consolidation.nasl");
  script_mandatory_keys("apache/struts/detected");

  script_xref(name:"URL", value:"https://cwiki.apache.org/confluence/display/WW/S2-057");
  script_xref(name:"URL", value:"https://semmle.com/news/apache-struts-CVE-2018-11776");
  script_xref(name:"URL", value:"https://lgtm.com/blog/apache_struts_CVE-2018-11776");
  script_xref(name:"Advisory-ID", value:"S2-057");

  script_tag(name:"summary", value:"Apache Struts is prone to a remote code execution
  (RCE) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to errors in conditions when
  namespace value isn't set for a result defined in underlying configurations and in same
  time, its upper action(s) configurations have no or wildcard namespace. Same possibility
  when using url tag which doesn't have value and action set and in same time, its upper
  action(s) configurations have no or wildcard namespace.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attacker to
  possibly conduct remote code on the affected application.");

  script_tag(name:"affected", value:"Apache Struts 2.3 through 2.3.34 and 2.5 through
  2.5.16.");

  script_tag(name:"solution", value:"Update to version 2.3.35, 2.5.17 or later.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(isnull(port = get_app_port(cpe:CPE)))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];

if(version_in_range(version:vers, test_version:"2.3.0", test_version2:"2.3.34"))
  fix = "2.3.35";

else if(version_in_range(version:vers, test_version:"2.5.0", test_version2:"2.5.16"))
  fix = "2.5.17";

if(fix) {
  report = report_fixed_ver(installed_version:vers, fixed_version:fix, install_path:infos["location"]);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);