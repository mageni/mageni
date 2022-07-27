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
  script_oid("1.3.6.1.4.1.25623.1.0.141997");
  script_version("$Revision: 13828 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-22 10:35:28 +0100 (Fri, 22 Feb 2019) $");
  script_tag(name:"creation_date", value:"2019-02-14 11:54:46 +0700 (Thu, 14 Feb 2019)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2019-5736");
  script_bugtraq_id(106976);

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Docker < 18.09.2 runc Command Execution Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_docker_remote_detect.nasl", "gb_docker_service_detection_lsc.nasl");
  script_mandatory_keys("docker/version");

  script_tag(name:"summary", value:"runc through 1.0-rc6, as used in Docker, allows attackers to overwrite the
host runc binary (and consequently obtain host root access) by leveraging the ability to execute a command as
root within one of these types of containers: (1) a new container with an attacker-controlled image, or (2) an
existing container, to which the attacker previously had write access, that can be attached with docker exec.
This occurs because of file-descriptor mishandling, related to /proc/self/exe.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Docker prior version 18.09.2.");

  script_tag(name:"solution", value:"Update to version 18.09.2 or later.");

  script_xref(name:"URL", value:"https://docs.docker.com/engine/release-notes/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_is_less(version: version, test_version: "18.09.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "18.09.2");
  security_message(port: 0, data: report);
  exit(0);
}

exit(0);
