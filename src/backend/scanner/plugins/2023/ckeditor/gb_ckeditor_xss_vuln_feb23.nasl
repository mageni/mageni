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

CPE = "cpe:/a:ckeditor:ckeditor";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126341");
  script_version("2023-02-16T10:08:32+0000");
  script_tag(name:"last_modification", value:"2023-02-16 10:08:32 +0000 (Thu, 16 Feb 2023)");
  script_tag(name:"creation_date", value:"2023-02-14 10:00:19 +0000 (Tue, 14 Feb 2023)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:N");

  script_cve_id("CVE-2022-48110");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"Mitigation");

  script_name("CKEditor 5 <= 35.4.0 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("sw_ckeditor_http_detect.nasl");
  script_mandatory_keys("ckeditor/detected");

  script_tag(name:"summary", value:"CKEditor 5 is prone to a cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"A cross-site scripting (XSS) vulnerability via the Full Featured
  CKEditor5 widget.");

  script_tag(name:"affected", value:"CKEditor 5 version 35.4.0. and prior.");

  script_tag(name:"solution", value:"The vendor's position is that this is not a vulnerability.
  The CKEditor 5 documentation discusses that it is the responsibility of an integrator (who is
  adding CKEditor 5 functionality to a website) to choose the correct security settings for their
  use case. Also, safe default values are established (e.g. config.htmlEmbed.showPreviews is
  false).");

  script_xref(name:"URL", value:"https://ckeditor.com/docs/ckeditor5/latest/features/html-embed.html");

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

if (version_is_less_equal(version: version, test_version: "35.4.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version:"See advisory", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(0);

