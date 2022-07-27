# Copyright (C) 2020 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

CPE = "cpe:/a:nodejs:node.js";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112789");
  script_version("2020-07-29T09:35:04+0000");
  script_tag(name:"last_modification", value:"2020-07-30 10:23:02 +0000 (Thu, 30 Jul 2020)");
  script_tag(name:"creation_date", value:"2020-07-29 09:06:11 +0000 (Wed, 29 Jul 2020)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2020-8174", "CVE-2020-11080");

  script_tag(name:"qod_type", value:"registry");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Node.js 10.x < 10.21.0, 12.x < 12.18.0, 14.x < 14.4.0 Multiple Vulnerabilities (Windows)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_nodejs_detect_win.nasl");
  script_mandatory_keys("Nodejs/Win/Ver");

  script_tag(name:"summary", value:"Node.js is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - napi_get_value_string_*() allows various kinds of memory corruption (CVE-2020-8174)

  - HTTP/2 Large Settings Frame DoS (CVE-2020-11080)");

  script_tag(name:"affected", value:"Node.js 10.x < 10.21.0, 12.x < 12.18.0, and 14.x < 14.4.0.");

  script_tag(name:"solution", value:"Update to version 10.21.0, 12.18.0 or 14.4.0 respectively.");

  script_xref(name:"URL", value:"https://nodejs.org/en/blog/vulnerability/june-2020-security-releases/");
  script_xref(name:"URL", value:"https://nodejs.org/en/blog/release/v10.21.0/");
  script_xref(name:"URL", value:"https://nodejs.org/en/blog/release/v12.18.0/");
  script_xref(name:"URL", value:"https://nodejs.org/en/blog/release/v14.4.0/");

  exit(0);

}

include("host_details.inc");
include("version_func.inc");

if(isnull(port = get_app_port(cpe:CPE)))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

vers = infos['version'];
path = infos['location'];

if(version_in_range(version:vers, test_version:"10.0", test_version2:"10.20.1")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"10.21.0", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

if(version_in_range(version:vers, test_version:"12.0", test_version2:"12.17.0")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"12.18.0", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

if(version_in_range(version:vers, test_version:"14.0", test_version2:"14.3.0")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"14.4.0", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
