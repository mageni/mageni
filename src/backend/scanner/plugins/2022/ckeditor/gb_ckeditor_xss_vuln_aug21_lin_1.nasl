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
  script_oid("1.3.6.1.4.1.25623.1.0.127127");
  script_version("2022-08-12T10:10:36+0000");
  script_tag(name:"last_modification", value:"2022-08-12 10:10:36 +0000 (Fri, 12 Aug 2022)");
  script_tag(name:"creation_date", value:"2022-08-10 08:55:19 +0000 (Wed, 10 Aug 2022)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-08-23 12:18:00 +0000 (Mon, 23 Aug 2021)");

  script_cve_id("CVE-2021-32808");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("CKEditor 4.13.0 < 4.16.2  XSS Vulnerability - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("sw_ckeditor_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("ckeditor/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"CKEditor is prone to a cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"The vulnerability allows to abuse undo functionality using
  malformed widget HTML, which results in JavaScript code execute.");

  script_tag(name:"affected", value:"CKEditor versions 4.13.0 through 4.16.1.");

  script_tag(name:"solution", value:"Update to version 4.16.2 or later.");

  script_xref(name:"URL", value:"https://github.com/ckeditor/ckeditor4/security/advisories/GHSA-6226-h7ff-ch6c");

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

if (version_in_range_exclusive(version: version, test_version_lo: "4.13.0", test_version_up: "4.16.2" )) {
    report = report_fixed_ver(inslled_version: version, fixed_version: "4.16.2", install_path: location);
    security_message(port: port, data: report);
    exit(0);
}

exit(99);
