# Copyright (C) 2022 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.113891");
  script_version("2022-04-13T06:19:51+0000");
  script_tag(name:"last_modification", value:"2022-04-13 10:28:29 +0000 (Wed, 13 Apr 2022)");
  script_tag(name:"creation_date", value:"2022-04-13 06:13:08 +0000 (Wed, 13 Apr 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-20 23:15:00 +0000 (Tue, 20 Jul 2021)");

  script_cve_id("CVE-2020-17530", "CVE-2021-31805");

  script_tag(name:"qod_type", value:"remote_banner_unreliable"); # nb: Only affected if a developer applied forced OGNL evaluation...

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Struts Security Update (S2-062)");

  script_category(ACT_GATHER_INFO);

  script_family("Web application abuses");
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_dependencies("gb_apache_struts_consolidation.nasl");
  script_mandatory_keys("apache/struts/detected");

  script_tag(name:"summary", value:"Apache Struts is prone to a remote code execution (RCE)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The fix issued for CVE-2020-17530 (S2-061) was incomplete. Still
  some of the tag's attributes could perform a double evaluation if a developer applied forced OGNL
  evaluation by using the %{...} syntax. Using forced OGNL evaluation on untrusted user input can
  lead to a Remote Code Execution and security degradation.");

  script_tag(name:"affected", value:"Apache Struts version 2.0.0 through 2.5.29.");

  script_tag(name:"solution", value:"Avoid using forced OGNL evaluation on untrusted user input,
  and/or upgrade to Struts 2.5.30 or greater which checks if expression evaluation won't lead to the
  double evaluation.");

  script_xref(name:"URL", value:"https://cwiki.apache.org/confluence/display/WW/S2-062");
  script_xref(name:"Advisory-ID", value:"S2-062");

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

if (version_in_range(version: version, test_version: "2.0.0", test_version2: "2.5.29")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.5.30", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);