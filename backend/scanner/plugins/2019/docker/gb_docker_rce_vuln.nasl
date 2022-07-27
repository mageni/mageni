# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) of the respective author(s)
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

CPE = 'cpe:/a:docker:docker';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142793");
  script_version("2019-08-27T02:19:19+0000");
  script_tag(name:"last_modification", value:"2019-08-27 02:19:19 +0000 (Tue, 27 Aug 2019)");
  script_tag(name:"creation_date", value:"2019-08-27 02:13:49 +0000 (Tue, 27 Aug 2019)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_cve_id("CVE-2019-13139");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Docker < 18.09.4 RCE Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_docker_remote_detect.nasl", "gb_docker_service_detection_lsc.nasl");
  script_mandatory_keys("docker/version");

  script_tag(name:"summary", value:"Docker is prone to a remote code execution vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An attacker who is capable of supplying or manipulating the build path for the
  'docker build' command would be able to gain command execution. An issue exists in the way 'docker build'
  processes remote git URLs, and results in command injection into the underlying 'git clone' command, leading to
  code execution in the context of the user executing the 'docker build' command. This occurs because git ref can
  be misinterpreted as a flag.");

  script_tag(name:"affected", value:"Docker prior version 18.09.4.");

  script_tag(name:"solution", value:"Update to version 18.09.4 or later.");

  script_xref(name:"URL", value:"https://docs.docker.com/engine/release-notes/#18094");
  script_xref(name:"URL", value:"https://github.com/moby/moby/pull/38944");
  script_xref(name:"URL", value:"https://staaldraad.github.io/post/2019-07-16-cve-2019-13139-docker-build/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_is_less(version: version, test_version: "18.09.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "18.09.4");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
