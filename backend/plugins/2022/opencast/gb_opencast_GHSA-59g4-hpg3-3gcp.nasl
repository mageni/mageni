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
  script_oid("1.3.6.1.4.1.25623.1.0.127022");
  script_version("2022-05-27T03:04:47+0000");
  script_tag(name:"last_modification", value:"2022-05-27 10:18:26 +0000 (Fri, 27 May 2022)");
  script_tag(name:"creation_date", value:"2022-05-26 09:46:28 +0000 (Thu, 26 May 2022)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-12-20 20:48:00 +0000 (Mon, 20 Dec 2021)");

  script_cve_id("CVE-2021-43821");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OpenCast < 10.6 Unauthorized File Access Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_opencast_detect.nasl");
  script_mandatory_keys("opencast/detected");

  script_tag(name:"summary", value:"OpenCast is prone to a unauthorized file access vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Opencast allows references to local file URLs in ingested media
  packages, allowing attackers to include local files from Opencast's host machines and making them
  available via the web interface.");

  script_tag(name:"impact", value:"Attackers could exploit this to include most local files
  the process has read access to, extracting secrets from the host machine.");

  script_tag(name:"affected", value:"OpenCast prior to version 10.6.");

  script_tag(name:"solution", value:"Update to version 10.6 or later.");

  script_xref(name:"URL", value:"https://github.com/opencast/opencast/security/advisories/GHSA-59g4-hpg3-3gcp");
  script_xref(name:"URL", value:"https://github.com/opencast/opencast/commit/65c46b9d3e8f045c544881059923134571897764");
  script_xref(name:"URL", value:"https://mvnrepository.com/artifact/org.opencastproject/opencast-ingest-service-impl");

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

if(version_is_less(version: version, test_version: "10.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.6", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
