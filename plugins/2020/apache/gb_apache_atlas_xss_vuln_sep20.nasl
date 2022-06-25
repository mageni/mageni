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

CPE = "cpe:/a:apache:atlas";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.144589");
  script_version("2020-09-17T06:57:26+0000");
  script_tag(name:"last_modification", value:"2020-09-17 10:14:55 +0000 (Thu, 17 Sep 2020)");
  script_tag(name:"creation_date", value:"2020-09-17 06:52:27 +0000 (Thu, 17 Sep 2020)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");

  script_cve_id("CVE-2020-13928");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Atlas 2.0.0 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_apache_atlas_detect.nasl");
  script_mandatory_keys("Apache/Atlas/Installed");

  script_tag(name:"summary", value:"Apache Atlas is prone to a cross-site scripting vulnerability in the
  basic search functionality.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Apache Atlas versions 2.0.0.");

  script_tag(name:"solution", value:"Update to Version 2.1.0 or later.");

  script_xref(name:"URL", value:"https://lists.apache.org/thread.html/ra468036f913be41b0c8fea74f91d53e273b0bfa838a4b140a5dcd463%40%3Cuser.atlas.apache.org%3E");

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

if (version_is_equal(version: version, test_version: "2.0.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.1.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
