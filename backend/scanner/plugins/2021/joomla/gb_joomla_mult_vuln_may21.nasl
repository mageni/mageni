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

CPE = "cpe:/a:joomla:joomla";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.146025");
  script_version("2021-05-27T07:15:46+0000");
  script_tag(name:"last_modification", value:"2021-05-27 10:33:26 +0000 (Thu, 27 May 2021)");
  script_tag(name:"creation_date", value:"2021-05-27 07:10:43 +0000 (Thu, 27 May 2021)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:N");

  script_cve_id("CVE-2021-26032", "CVE-2021-26033", "CVE-2021-26034");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Joomla! 3.0.0 - 3.9.26 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_mandatory_keys("joomla/installed");

  script_tag(name:"summary", value:"Joomla! is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2021-26032: HTML is missing in the executable block list of MediaHelper::canUpload, leading
    to XSS attack vectors

  - CVE-2021-26033: A missing token check causes a CSRF vulnerability in the AJAX reordering endpoint

  - CVE-2021-26034: A missing token check causes a CSRF vulnerability in data download endpoints
    in com_banners and com_sysinfo");

  script_tag(name:"affected", value:"Joomla! version 3.0.0 through 3.9.26.");

  script_tag(name:"solution", value:"Update to version 3.9.27 or later.");

  script_xref(name:"URL", value:"https://developer.joomla.org/security-centre/852-20210501-core-adding-html-to-the-executable-block-list-of-mediahelper-canupload.html");
  script_xref(name:"URL", value:"https://developer.joomla.org/security-centre/853-20210502-core-csrf-in-ajax-reordering-endpoint.html");
  script_xref(name:"URL", value:"https://developer.joomla.org/security-centre/854-20210503-core-csrf-in-data-download-endpoints.html");

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

if (version_in_range(version: version, test_version: "3.0.0", test_version2: "3.9.26")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.9.27", install_path: location);
  security_message(data: report, port: port);
  exit(0);
}

exit(99);
