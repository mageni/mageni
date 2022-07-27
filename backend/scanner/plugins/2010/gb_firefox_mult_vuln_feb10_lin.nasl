# Copyright (C) 2010 Greenbone Networks GmbH
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

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900743");
  script_version("2021-11-22T14:21:24+0000");
  script_tag(name:"last_modification", value:"2021-11-22 14:21:24 +0000 (Mon, 22 Nov 2021)");
  script_tag(name:"creation_date", value:"2010-02-22 13:34:53 +0100 (Mon, 22 Feb 2010)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2010-0648", "CVE-2010-0654", "CVE-2011-2669", "CVE-2011-2670");
  script_name("Firefox < 3.6 Multiple Vulnerabilities - Linux");
  script_xref(name:"URL", value:"http://code.google.com/p/chromium/issues/detail?id=9877");
  script_xref(name:"URL", value:"http://code.google.com/p/chromium/issues/detail?id=32309");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("mozilla/firefox/linux/detected");

  script_tag(name:"affected", value:"Mozilla Firefox versions prior to 3.6.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2010-0654: The malformed stylesheet document and cross-origin loading of CSS stylesheets
  even when the stylesheet download has an incorrect MIME type.

  - CVE-2010-0648: IFRAME element allows placing the site's URL in the HREF attribute of a
  stylesheet 'LINK' element, and then reading the 'document.styleSheets[0].href' property value.

  - CVE-2011-2669: Denial-of-service (DoS) vulnerability due to an issue in the validation of
  certificates.

  - CVE-2011-2670: Cross-site scripting (XSS) via the rendering of Cascading Style Sheets.");

  script_tag(name:"solution", value:"Update to version 3.6 or later.");

  script_tag(name:"summary", value:"Mozilla Firefox is prone to multiple vulnerabilities.");

  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_version_and_location(cpe: CPE, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "3.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.6", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);