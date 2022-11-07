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

CPE = "cpe:/a:exim:exim";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126183");
  script_version("2022-10-25T10:13:35+0000");
  script_tag(name:"last_modification", value:"2022-10-25 10:13:35 +0000 (Tue, 25 Oct 2022)");
  script_tag(name:"creation_date", value:"2022-10-21 10:31:17 +0000 (Fri, 21 Oct 2022)");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2022-3620");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Exim 4.95 - 4.96 Use-After-Free Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_exim_detect.nasl");
  script_mandatory_keys("exim/installed");

  script_tag(name:"summary", value:"Exim is prone to a use-after-free vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Exim has an use-after-free in dmarc_dns_lookup where the result
  of dns_lookup in dnsa is freed before the required data is copied out.");

  script_tag(name:"affected", value:"Exim version 4.95 through 4.96.

  Note: The issue has been introduced with commit 92583637b25b6bde926f9ca6be7b085e5ac8b1e6
  included in the final release 4.95 and has been fixed with the commit
  12fb3842f81bcbd4a4519d5728f2d7e0e3ca1445 included in the next upcoming version 4.97.");

  # nb: Fixed version wasn't released yet, but the flaw is already fixed and will be released in upcoming patch.
  script_tag(name:"solution", value:"Update to version 4.97 or later.");

  script_xref(name:"URL", value:"https://github.com/Exim/exim/commit/12fb3842f81bcbd4a4519d5728f2d7e0e3ca1445");
  script_xref(name:"URL", value:"https://github.com/Exim/exim/commit/92583637b25b6bde926f9ca6be7b085e5ac8b1e6");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe: CPE))
  exit(0);

if(!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if(version_in_range(version: version, test_version: "4.95", test_version2: "4.96")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.97");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
