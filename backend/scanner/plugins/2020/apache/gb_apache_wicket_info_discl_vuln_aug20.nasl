# Copyright (C) 2020 Greenbone Networks GmbH
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

CPE = "cpe:/a:apache:wicket";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.144384");
  script_version("2020-08-12T03:14:36+0000");
  script_tag(name:"last_modification", value:"2020-08-12 10:28:50 +0000 (Wed, 12 Aug 2020)");
  script_tag(name:"creation_date", value:"2020-08-12 02:31:15 +0000 (Wed, 12 Aug 2020)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2020-11976");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Wicket 7.16.0, 8.8.0, 9.0.0-M5 Information Disclosure Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_etcd_detect.nasl");
  script_mandatory_keys("etcd/installed");

  script_tag(name:"summary", value:"Apache Wicket is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"By crafting a special URL it is possible to make Wicket deliver unprocessed
  HTML templates. This would allow an attacker to see possibly sensitive information inside a HTML template that
  is usually removed during rendering. For example if there are credentials in the markup which are never
  supposed to be visible to the client");

  script_tag(name:"affected", value:"Apache Wicket 7.16.0, 8.8.0 and 9.0.0-M5.");

  script_tag(name:"solution", value:"Update to version 7.17.0, 8.9.0, 9.0.0 or later.");

  script_xref(name:"URL", value:"https://lists.apache.org/thread.html/r104eeefeb1e9da51f7ef79cef0f9ff12e21ef8559b77801e86b21e16%40%3Cusers.wicket.apache.org%3E");

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

if (version == "7.16.0") {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.17.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version == "8.8.0") {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.9.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version == "9.0.0.M5") {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.0.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
