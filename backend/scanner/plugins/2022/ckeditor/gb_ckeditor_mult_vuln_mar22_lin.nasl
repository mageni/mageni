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

CPE = "cpe:/a:ckeditor:ckeditor";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147815");
  script_version("2022-03-21T05:18:39+0000");
  script_tag(name:"last_modification", value:"2022-03-21 05:18:39 +0000 (Mon, 21 Mar 2022)");
  script_tag(name:"creation_date", value:"2022-03-21 05:13:19 +0000 (Mon, 21 Mar 2022)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_cve_id("CVE-2022-24728", "CVE-2022-24729");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("CKEditor 4.x < 4.18.0 Multiple Vulnerabilities - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("sw_ckeditor_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("ckeditor/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"CKEditor is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2022-24728: HTML processing vulnerability allowing to execute JavaScript code

  - CVE-2022-24729: Regular expression denial of service (DoS) in dialog plugin");

  script_tag(name:"affected", value:"CKEditor version 4.x prior to 4.18.0.");

  script_tag(name:"solution", value:"Update to version 4.18.0 or later");

  script_xref(name:"URL", value:"https://github.com/ckeditor/ckeditor4/security/advisories/GHSA-4fc4-4p5g-6w89");
  script_xref(name:"URL", value:"https://github.com/ckeditor/ckeditor4/security/advisories/GHSA-f6rf-9m92-x2hh");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range_exclusive(version: version, test_version_lo: "4.0", test_version_up: "4.18.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version:"4.18.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
