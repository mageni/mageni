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

CPE = "cpe:/a:openssl:openssl";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.117595");
 script_version("2021-07-29T13:31:06+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-07-29 13:31:06 +0000 (Thu, 29 Jul 2021)");
  script_tag(name:"creation_date", value:"2021-07-29 13:23:43 +0000 (Thu, 29 Jul 2021)");

  script_cve_id("CVE-2014-8176");

  script_bugtraq_id(75159);

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OpenSSL Denial of Service Vulnerability (20150611 - 3) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_openssl_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("openssl/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"OpenSSL is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"If a DTLS peer receives application data between the
  ChangeCipherSpec and Finished messages, buffering of such data may cause an invalid free,
  resulting in a segmentation fault or potentially, memory corruption.");

  script_tag(name:"affected", value:"OpenSSL version 0.9.8 through 0.9.8y, 1.0.0 through 1.0.0l and
  1.0.1 through 1.0.1g.");

  script_tag(name:"solution", value:"Update to version 0.9.8za, 1.0.0m, 1.0.1h or later.");

  script_xref(name:"URL", value:"https://www.openssl.org/news/secadv/20150611.txt");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(isnull(port = get_app_port(cpe:CPE)))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_in_range(version:vers, test_version:"0.9.8", test_version2:"0.9.8y")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"0.9.8za", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

if(version_in_range(version:vers, test_version:"1.0.0", test_version2:"1.0.0l")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"1.0.0m", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

if(version_in_range(version:vers, test_version:"1.0.1", test_version2:"1.0.1g")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"1.0.1h", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);