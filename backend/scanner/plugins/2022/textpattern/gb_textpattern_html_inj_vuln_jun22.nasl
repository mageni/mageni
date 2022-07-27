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

CPE = "cpe:/a:textpattern:textpattern";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126042");
  script_version("2022-06-16T10:34:25+0000");
  script_tag(name:"last_modification", value:"2022-06-17 09:50:23 +0000 (Fri, 17 Jun 2022)");
  script_tag(name:"creation_date", value:"2022-06-16 12:39:37 +0000 (Thu, 16 Jun 2022)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:N");

  script_cve_id("CVE-2021-40658");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_name("Textpattern CMS <= 4.8.7 HTML Injection Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_textpattern_cms_http_detect.nasl");
  script_mandatory_keys("textpattern_cms/detected");

  script_tag(name:"summary", value:"Textpattern CMS is prone to a HTML injection
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Textpattern is vulnerable to a html injection
  through Content>Write>Body. This might lead to inject arbitrary html and script
  code into the web site.");

  script_tag(name:"affected", value:"Textpattern CMS version 4.8.7 and probably prior.");

  script_tag(name:"solution", value:"No known solution is available as of 16th June, 2022.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://tanmay26.medium.com/textpattern-4-8-7-is-affected-by-html-injection-in-the-body-parameter-1a7be2441b70");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less_equal(version: version, test_version: "4.8.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "None");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
