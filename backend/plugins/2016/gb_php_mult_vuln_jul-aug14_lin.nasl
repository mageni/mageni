# Copyright (C) 2016 Greenbone Networks GmbH
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

CPE = "cpe:/a:php:php";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809736");
  script_version("2021-11-25T10:16:15+0000");
  # nb: CVE-2014-9912 isn't listed on the ChangeLog page but affects the very same versions
  # according to the NVD entry so it was added here.
  script_cve_id("CVE-2014-3981", "CVE-2014-4721", "CVE-2014-0207", "CVE-2014-3478", "CVE-2014-3479",
                "CVE-2014-3480", "CVE-2014-3487", "CVE-2014-4049", "CVE-2014-3515", "CVE-2014-9912");
  script_bugtraq_id(67837, 68423, 68239, 68237, 68243, 68120, 68241, 68238);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-11-26 11:17:40 +0000 (Fri, 26 Nov 2021)");
  script_tag(name:"creation_date", value:"2016-12-01 18:38:59 +0530 (Thu, 01 Dec 2016)");
  script_name("PHP Multiple Vulnerabilities (Jun/Aug 2014) - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_php_ssh_login_detect.nasl", "gb_php_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("php/detected", "Host/runs_unixoide");

  script_xref(name:"URL", value:"http://php.net/ChangeLog-5.php");
  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=67390");
  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=67498");
  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=67326");
  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=67410");
  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=67411");
  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=67412");
  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=67413");
  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=67432");
  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=67492");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2014/Jun/21");
  script_xref(name:"URL", value:"https://www.sektioneins.de/en/blog/14-07-04-phpinfo-infoleak.html");
  script_xref(name:"URL", value:"http://secunia.com/advisories/59575");

  script_tag(name:"summary", value:"PHP is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - Fixed bug #67390 (insecure temporary file use in the configure script). (CVE-2014-3981).

  - Fixed bug #67498 (phpinfo() Type Confusion Information Leak Vulnerability). (CVE-2014-4721).

  - Fixed bug #67326 (cdf_read_short_sector insufficient boundary check). (CVE-2014-0207).

  - Fixed bug #67410 (mconvert incorrect handling of truncated pascal string size). (CVE-2014-3478).

  - Fixed bug #67411 (cdf_check_stream_offset insufficient boundary check). (CVE-2014-3479).

  - Fixed bug #67412 (cdf_count_chain insufficient boundary check). (CVE-2014-3480).

  - Fixed bug #67413 (cdf_read_property_info insufficient boundary check). (CVE-2014-3487).

  - Fixed bug #67432 (Fix potential segfault in dns_get_record()). (CVE-2014-4049).

  - Fixed bug #67492 (unserialize() SPL ArrayObject / SPLObjectStorage Type Confusion).
  (CVE-2014-3515).

  - Fixed bug #67397 (Buffer overflow in locale_get_display_name and uloc_getDisplayName (libicu
  4.8.1)). (CVE-2014-9912).");

  script_tag(name:"affected", value:"PHP versions 5.3.x before 5.3.29, 5.4.x before 5.4.30 and 5.5.x
  before 5.5.14.");

  script_tag(name:"solution", value:"Update to version 5.3.29, 5.4.30, 5.5.14 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(isnull(port = get_app_port(cpe:CPE)))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
loc = infos["location"];

if(vers =~ "^5\.") {
  if(version_in_range(version:vers, test_version:"5.3",test_version2:"5.3.28")) {
    VULN = TRUE;
    fix = "5.3.29";
  }

  else if(version_in_range(version:vers, test_version:"5.4",test_version2:"5.4.29")) {
    VULN = TRUE;
    fix = "5.4.30";
  }

  else if(version_in_range(version:vers, test_version:"5.5",test_version2:"5.5.13")) {
    VULN = TRUE;
    fix = "5.5.14";
  }

  if(VULN) {
    report = report_fixed_ver(installed_version:vers, fixed_version:fix, install_path:loc);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);