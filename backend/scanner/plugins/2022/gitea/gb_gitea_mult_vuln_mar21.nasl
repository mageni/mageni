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

CPE = "cpe:/a:gitea:gitea";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124039");
  script_version("2022-03-18T08:37:23+0000");
  script_tag(name:"last_modification", value:"2022-03-18 11:33:43 +0000 (Fri, 18 Mar 2022)");
  script_tag(name:"creation_date", value:"2022-03-17 17:04:03 +0000 (Thu, 17 Mar 2022)");
  script_tag(name:"cvss_base", value:"5.2");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:S/C:P/I:P/A:P");

  script_cve_id("CVE-2021-29134");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Gitea < 1.13.6 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_gitea_detect.nasl");
  script_mandatory_keys("gitea/detected");

  script_tag(name:"summary", value:"Gitea is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2021-29134: A path traversal vulnerability exists via the avatar middleware

  - No CVE: An unnamed security vulnerability in modules/markup/html.go");

  script_tag(name:"affected", value:"Gitea prior to version 1.13.6.");

  script_tag(name:"solution", value:"Update to version 1.13.6 or later.");

  script_xref(name:"URL", value:"https://blog.gitea.io/2021/03/gitea-1.13.6-is-released/");
  script_xref(name:"URL", value:"https://github.com/go-gitea/gitea/pull/15125");
  script_xref(name:"URL", value:"https://github.com/go-gitea/gitea/pull/15096");
  script_xref(name:"URL", value:"https://github.com/go-gitea/gitea/releases/tag/v1.13.6");

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

if (version_is_less(version: version, test_version: "1.13.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.13.6", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
