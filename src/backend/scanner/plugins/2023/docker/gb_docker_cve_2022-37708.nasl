# Copyright (C) 2023 Greenbone Networks GmbH
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

CPE = "cpe:/a:docker:docker";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.104559");
  script_version("2023-02-24T10:08:40+0000");
  script_tag(name:"last_modification", value:"2023-02-24 10:08:40 +0000 (Fri, 24 Feb 2023)");
  script_tag(name:"creation_date", value:"2023-02-24 08:36:18 +0000 (Fri, 24 Feb 2023)");
  script_tag(name:"cvss_base", value:"6.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:C/I:C/A:N");

  script_cve_id("CVE-2022-37708");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_name("Docker <= 20.10.15 build fd8262 Insecure Permissions Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_docker_http_rest_api_detect.nasl", "gb_docker_ssh_login_detect.nasl");
  script_mandatory_keys("docker/version");

  script_tag(name:"summary", value:"Docker is prone to an insecure permissions vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Unauthorized users outside the Docker container can access any
  files within the Docker container.");

  script_tag(name:"affected", value:"Docker version 20.10.15 build fd8262 and prior.");

  script_tag(name:"solution", value:"No known solution is available as of 24th February, 2023.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://github.com/advisories/GHSA-p779-957q-8gq3");
  script_xref(name:"URL", value:"https://github.com/thekevinday/docker_lightman_exploit");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_is_less_equal(version: version, test_version: "20.10.15")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "None");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
