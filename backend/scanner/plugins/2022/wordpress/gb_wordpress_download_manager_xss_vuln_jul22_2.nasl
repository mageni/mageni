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

CPE = "cpe:/a:wpdownloadmanager:wordpress_download_manager";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124125");
  script_version("2022-07-20T14:02:41+0000");
  script_tag(name:"last_modification", value:"2022-07-20 14:02:41 +0000 (Wed, 20 Jul 2022)");
  script_tag(name:"creation_date", value:"2022-07-19 08:08:38 +0000 (Tue, 19 Jul 2022)");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:N");

  script_cve_id("CVE-2022-2101");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Download Manager Plugin <= 3.2.46 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/download-manager/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Download Manager' is prone to a cross-site
  scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The plugin is vulnerable to Stored Cross-Site Scripting via
  the `file[files][]` parameter due to insufficient input sanitization and output escaping. This
  makes it possible for authenticated attackers with contributor level permissions and above to
  inject arbitrary web scripts on the file's page that will execute whenever an administrator
  accesses the editor area for the injected file page.");

  script_tag(name:"affected", value:"WordPress Download Manager plugin prior to version 3.2.47.");

  script_tag(name:"solution", value:"Update to version 3.2.47 or later.");

  script_xref(name:"URL", value:"https://www.wordfence.com/vulnerability-advisories/#CVE-2022-2101");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less_equal(version: version, test_version: "3.2.46")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.2.47", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
