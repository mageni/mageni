# Copyright (C) 2021 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

CPE = "cpe:/a:concrete5:concrete5";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.146410");
  script_version("2021-08-02T03:42:52+0000");
  script_tag(name:"last_modification", value:"2021-08-02 10:50:44 +0000 (Mon, 02 Aug 2021)");
  script_tag(name:"creation_date", value:"2021-08-02 03:36:58 +0000 (Mon, 02 Aug 2021)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_cve_id("CVE-2021-36766");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_name("Concrete5 <= 8.5.5 Phar Deserialization Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_concrete5_detect.nasl");
  script_mandatory_keys("concrete5/installed");

  script_tag(name:"summary", value:"Concrete5 is prone to a deserialization vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Concrete5 deserializes untrusted Data. The vulnerable code is
  located within the controllers/single_page/dashboard/system/environment/logging.php
  Logging::update_logging() method. User input passed through the logFile request parameter is not
  properly sanitized before being used in a call to the file_exists() PHP function. This can be
  exploited by malicious users to inject arbitrary PHP objects into the application scope (PHP
  Object Injection via phar:// stream wrapper), allowing them to carry out a variety of attacks,
  such as executing arbitrary PHP code.");

  script_tag(name:"affected", value:"Concrete5 version 8.5.5 and prior.");

  script_tag(name:"solution", value:"No known solution is available as of 02nd August, 2021.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"http://karmainsecurity.com/KIS-2021-05");

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

if (version_is_less_equal(version: version, test_version: "8.5.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "None", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
