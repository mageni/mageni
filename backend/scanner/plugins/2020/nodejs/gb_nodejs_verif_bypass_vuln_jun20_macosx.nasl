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
  script_oid("1.3.6.1.4.1.25623.1.0.112791");
  script_version("2020-07-29T09:35:04+0000");
  script_tag(name:"last_modification", value:"2020-07-30 10:23:02 +0000 (Thu, 30 Jul 2020)");
  script_tag(name:"creation_date", value:"2020-07-29 09:06:11 +0000 (Wed, 29 Jul 2020)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");

  script_cve_id("CVE-2020-8172");

  script_tag(name:"qod_type", value:"executable_version");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Node.js 12.x < 12.18.0, 14.x < 14.4.0 Host Certificate Verification Bypass Vulnerability (Mac OS X)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_nodejs_detect_macosx.nasl");
  script_mandatory_keys("Nodejs/MacOSX/Ver");

  script_tag(name:"summary", value:"Node.js is prone to a host certificate verification bypass.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A TLS session reuse can lead to host certificate verification bypass.");

  script_tag(name:"affected", value:"Node.js 12.x < 12.18.0, and 14.x < 14.4.0.");

  script_tag(name:"solution", value:"Update to version 12.18.0 or 14.4.0 respectively.");

  script_xref(name:"URL", value:"https://nodejs.org/en/blog/vulnerability/june-2020-security-releases/");
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
