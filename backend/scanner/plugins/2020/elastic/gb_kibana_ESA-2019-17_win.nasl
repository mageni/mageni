# Copyright (C) 2020 Greenbone Networks GmbH
# Text descriptions excerpted from a referenced source are Copyright (C)
# of the respective author(s)
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

CPE = "cpe:/a:elasticsearch:kibana";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143410");
  script_version("2020-01-28T04:38:38+0000");
  script_tag(name:"last_modification", value:"2020-01-28 04:38:38 +0000 (Tue, 28 Jan 2020)");
  script_tag(name:"creation_date", value:"2020-01-28 04:37:41 +0000 (Tue, 28 Jan 2020)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");

  script_cve_id("CVE-2019-7621");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Elastic Kibana < 6.8.6, 7.x < 7.5.1 XSS Vulnerability (Windows)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_elasticsearch_kibana_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("Elasticsearch/Kibana/Installed", "Host/runs_windows");

  script_tag(name:"summary", value:"Kibana is prone to a cross-site scripting vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Kibana contains a cross site scripting (XSS) flaw in the coordinate and region
  map visualizations. An attacker with the ability to create coordinate map visualizations could create a
  malicious visualization. If another Kibana user views that visualization or a dashboard containing the
  visualization it could execute JavaScript in the victim's browser.");

  script_tag(name:"affected", value:"Kibana versions prior to 6.8.6 and 7.5.1.");

  script_tag(name:"solution", value:"Update to version 6.8.6, 7.5.1 or later.");

  script_xref(name:"URL", value:"https://discuss.elastic.co/t/elastic-stack-6-8-6-and-7-5-1-security-update/212390");

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

if (version_is_less(version: version, test_version: "6.8.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.8.6", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "7.0", test_version2: "7.5.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.5.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
