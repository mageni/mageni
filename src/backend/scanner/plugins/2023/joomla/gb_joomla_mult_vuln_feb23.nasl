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

CPE = "cpe:/a:joomla:joomla";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126324");
  script_version("2023-02-09T10:17:23+0000");
  script_tag(name:"last_modification", value:"2023-02-09 10:17:23 +0000 (Thu, 09 Feb 2023)");
  script_tag(name:"creation_date", value:"2023-02-02 03:10:21 +0000 (Thu, 02 Feb 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2023-23750", "CVE-2023-23751");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Joomla! 4.0.0 <= 4.2.6 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_mandatory_keys("joomla/installed");

  script_tag(name:"summary", value:"Joomla! is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exit:

  - CVE-2023-23750: A missing token check causes a CSRF vulnerability in the handling of post-installation messages.

  - CVE-2023-23751: A missing ACL check allows non super-admin users to access com_actionlogs.");

  script_tag(name:"affected", value:"Joomla! version 4.0.0 through 4.2.6.");

  script_tag(name:"solution", value:"Update to version 4.2.7 or later.");

  script_xref(name:"URL", value:"https://developer.joomla.org/security-centre/890-20230101-core-csrf-within-post-installation-messages.html");
  script_xref(name:"URL", value:"https://developer.joomla.org/security-centre/891-20230102-core-missing-acl-checks-for-com-actionlogs.html");

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

if (version_in_range(version: version, test_version: "4.0.0", test_version2: "4.2.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.2.7", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
