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

CPE = "cpe:/a:opencast:opencast";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127021");
  script_version("2022-05-27T03:04:47+0000");
  script_tag(name:"last_modification", value:"2022-05-27 10:18:26 +0000 (Fri, 27 May 2022)");
  script_tag(name:"creation_date", value:"2022-05-26 09:28:28 +0000 (Thu, 26 May 2022)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-12-20 13:31:00 +0000 (Mon, 20 Dec 2021)");

  script_cve_id("CVE-2021-43807");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OpenCast < 9.10 HTTP Method Spoofing Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_opencast_detect.nasl");
  script_mandatory_keys("opencast/detected");

  script_tag(name:"summary", value:"OpenCast is prone to an HTTP method spoofing vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Opencast allows HTTP method spoofing, allowing to change the
  assumed HTTP method via URL parameter. This allows attackers to turn HTTP GET requests into PUT
  requests or an HTTP form to send DELETE requests. This bypasses restrictions otherwise put on
  these types of requests and aids in cross-site request forgery (CSRF) attacks, which would
  otherwise not be possible.");

  script_tag(name:"impact", value:"The vulnerability allows attackers to craft links or forms which
  may change the server state.");

  script_tag(name:"affected", value:"OpenCast prior to version 9.10.");

  script_tag(name:"solution", value:"Update to version 9.10 or later.");

  script_xref(name:"URL", value:"https://github.com/opencast/opencast/security/advisories/GHSA-j4mm-7pj3-jf7v");
  script_xref(name:"URL", value:"https://github.com/opencast/opencast/commit/8f8271e1085f6f8e306c689d6a56b0bb8d076444");
  script_xref(name:"URL", value:"https://github.com/opencast/opencast/commit/59cb6731067283e54f15462be38b6117d8b9ea8b#diff-9c5fb3d1b7e3b0f54bc5c4182965c4fe1f9023d449017cece3005d3f90e8e4d8");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe: CPE))
  exit(0);

if(!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if(version_is_less(version: version, test_version: "9.10")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.10", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
