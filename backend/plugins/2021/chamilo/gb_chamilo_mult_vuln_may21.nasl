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

CPE = "cpe:/a:chamilo:chamilo_lms";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.146494");
  script_version("2021-08-11T09:43:36+0000");
  script_tag(name:"last_modification", value:"2021-08-11 10:24:47 +0000 (Wed, 11 Aug 2021)");
  script_tag(name:"creation_date", value:"2021-08-11 05:47:25 +0000 (Wed, 11 Aug 2021)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2021-32925", "CVE-2021-34187", "CVE-2021-37389", "CVE-2021-37390", "CVE-2021-37391");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_name("Chamilo LMS <= 1.11.14 Multiple Vulnerabilities (May 2021)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_chamilo_http_detect.nasl");
  script_mandatory_keys("chamilo/detected");

  script_tag(name:"summary", value:"Chamilo LMS is prone to multiple vulnerabilities.");

  script_tag(name:"impact", value:"The following vulnerabilities exist:

  - CVE-2021-32925: XML External Entity (XXE)

  - CVE-2021-34187: SQL injection

  - CVE-2021-37389, CVE-2021-37390, CVE-2021-37391: Multiple cross-site scripting (XSS)");

  script_tag(name:"affected", value:"Chamilo version 1.11.14 and prior.");

  script_tag(name:"solution", value:"No known solution is available as of 11th August, 2021.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://github.com/chamilo/chamilo-lms/commit/e71437c8de809044ba3ae1b181d70857c050a3e9");
  script_xref(name:"URL", value:"https://github.com/chamilo/chamilo-lms/commit/005dc8e9eccc6ea35264064ae09e2e84af8d5b59");
  script_xref(name:"URL", value:"https://github.com/chamilo/chamilo-lms/commit/f7f93579ed64765c2667910b9c24d031b0a00571");
  script_xref(name:"URL", value:"https://github.com/chamilo/chamilo-lms/commit/dfae49f5dc392c00cd43badcb3043db3a646ff0c");
  script_xref(name:"URL", value:"https://github.com/chamilo/chamilo-lms/commit/3fcc751d5cc7da311532a8756fba5a8778f50ca0");
  script_xref(name:"URL", value:"https://github.com/chamilo/chamilo-lms/commit/de43a77049771cce08ea7234c5c1510b5af65bc8");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less_equal(version: version, test_version: "1.11.14")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "None", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
