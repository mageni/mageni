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

CPE = "cpe:/a:openwrt:openwrt";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126146");
  script_version("2022-09-21T10:12:28+0000");
  script_tag(name:"last_modification", value:"2022-09-21 10:12:28 +0000 (Wed, 21 Sep 2022)");
  script_tag(name:"creation_date", value:"2022-09-20 09:05:35 +0000 (Tue, 20 Sep 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2022-38333");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OpenWRT < 22.03.0 Information Disclosure Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_openwrt_ssh_login_detect.nasl");
  script_mandatory_keys("openwrt/detected");

  script_tag(name:"summary", value:"OpenWRT is prone to a information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"By passing specially crafted header values, the skip loops in
  the header_value() function may override the input buffer by one byte each.");

  script_tag(name:"impact", value:"This vulnerability allows attackers to access sensitive
  information via a crafted HTTP request.");

  script_tag(name:"affected", value:"OpenWRT prior to version 22.03.0.");

  script_tag(name:"solution", value:"Update to version 22.03.0 or later.");

  script_xref(name:"URL", value:"https://openwrt.org/releases/22.03/notes-22.03.0");
  script_xref(name:"URL", value:"https://git.openwrt.org/?p=project/cgi-io.git;a=commitdiff;h=901b0f0463c9d16a8cf5b9ed37118d8484bc9176");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_is_less(version: version, test_version: "22.03.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "22.03.0");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
