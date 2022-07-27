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

CPE = "cpe:/a:twistedmatrix:twisted";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147821");
  script_version("2022-03-22T02:12:12+0000");
  script_tag(name:"last_modification", value:"2022-03-22 11:26:02 +0000 (Tue, 22 Mar 2022)");
  script_tag(name:"creation_date", value:"2022-03-22 01:54:44 +0000 (Tue, 22 Mar 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2022-21712");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Twisted Web 11.1 < 22.1 Information Disclosure Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_twistedweb_http_detect.nasl");
  script_mandatory_keys("twistedweb/detected");

  script_tag(name:"summary", value:"Twisted Web is prone to an information disclosure
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Cookie and Authorization headers are leaked when following
  cross-origin redirects in twited.web.client.RedirectAgent and
  twisted.web.client.BrowserLikeRedirectAgent.");

  script_tag(name:"affected", value:"Twisted Web version 11.1 through 22.0.");

  script_tag(name:"solution", value:"Update to version 22.1 or later.");

  script_xref(name:"URL", value:"https://github.com/twisted/twisted/security/advisories/GHSA-92x2-jw7w-xvvx");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range_exclusive(version: version, test_version_lo: "11.1", test_version_up: "22.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "22.1");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
