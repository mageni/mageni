# Copyright (C) 2019 Greenbone Networks GmbH
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

CPE = "cpe:/a:cesanta:mongoose";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142639");
  script_version("2019-07-23T08:22:12+0000");
  script_tag(name:"last_modification", value:"2019-07-23 08:22:12 +0000 (Tue, 23 Jul 2019)");
  script_tag(name:"creation_date", value:"2019-07-23 08:18:18 +0000 (Tue, 23 Jul 2019)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2019-13503");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_name("Mongoose <= 6.15 Buffer Overflow Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_mongoose_web_server_detect.nasl");
  script_mandatory_keys("Cesanta/Mongoose/installed");

  script_tag(name:"summary", value:"Mongoose is prone to a heap-based buffer overflow in mq_parse_http().");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Mongoose 6.15 and probably prior.");

  script_tag(name:"solution", value:"No known solution is available as of 23rd July, 2019.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://github.com/cesanta/mongoose/pull/1035");
  script_xref(name:"URL", value:"https://fuzzit.dev/2019/07/11/discovering-cve-2019-13504-cve-2019-13503-and-the-importance-of-api-fuzzing/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos['version'];
location = infos['location'];

if (version_is_less_equal(version: version, test_version: "6.15")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "None", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
