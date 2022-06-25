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

CPE = "cpe:/a:docker:docker";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.145328");
  script_version("2021-02-08T03:14:51+0000");
  script_tag(name:"last_modification", value:"2021-02-08 11:02:13 +0000 (Mon, 08 Feb 2021)");
  script_tag(name:"creation_date", value:"2021-02-08 03:06:25 +0000 (Mon, 08 Feb 2021)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_cve_id("CVE-2021-21284", "CVE-2021-21285");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Docker < 19.03.15, 20.x < 20.10.3 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_docker_remote_detect.nasl", "gb_docker_service_detection_lsc.nasl");
  script_mandatory_keys("docker/version");

  script_tag(name:"summary", value:"Docker is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - Access to remapped root allows privilege escalation to real root (CVE-2021-21284)

  - Docker daemon crash during image pull of malicious image (CVE-2021-21285)");

  script_tag(name:"affected", value:"Docker prior to versions 19.03.15 or 20.10.3.");

  script_tag(name:"solution", value:"Update to version 19.03.15, 20.10.3 or later.");

  script_xref(name:"URL", value:"https://github.com/moby/moby/security/advisories/GHSA-7452-xqpj-6rpc");
  script_xref(name:"URL", value:"https://github.com/moby/moby/security/advisories/GHSA-6fj5-m822-rqx8");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_is_less(version: version, test_version: "19.03.15")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "19.03.15");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "20.10", test_version2: "20.10.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "20.10.3");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
