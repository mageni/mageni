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

CPE = "cpe:/a:eyes_of_network:eyes_of_network";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126117");
  script_version("2022-08-17T12:28:18+0000");
  script_tag(name:"last_modification", value:"2022-08-17 12:28:18 +0000 (Wed, 17 Aug 2022)");
  script_tag(name:"creation_date", value:"2022-08-17 10:28:02 +0000 (Wed, 17 Aug 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2022-38357", "CVE-2022-38358", "CVE-2022-38359");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_name("Eyes Of Network (EON) 5.3 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_eyesofnetwork_detect.nasl");
  script_mandatory_keys("eyesofnetwork/detected");

  script_tag(name:"summary", value:"Eyes Of Network (EON) is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2022-38357: The url parameter of /module/module_frame/index.php is vulnerable to iFrame
  injection.

  - CVE-2022-38358: Cross-site scripting (XSS) via /module/admin_notifier/rules.php.

  - CVE-2022-38359: Cross-site scripting (XSS) via /module/report_event/index.php.");

  script_tag(name:"affected", value:"Eyes Of Network version 5.3 and probably prior.");

  script_tag(name:"solution", value:"No known solution is available as of 17th August, 2022.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://www.tenable.com/security/research/tra-2022-29");
  script_xref(name:"URL", value:"https://www.tenable.com/cve/CVE-2022-38357");
  script_xref(name:"URL", value:"https://www.tenable.com/cve/CVE-2022-38358");
  script_xref(name:"URL", value:"https://www.tenable.com/cve/CVE-2022-38359");


  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_is_less_equal(version: version, test_version: "5.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "None");
  security_message(port: 0, data: report);
  exit(0);
}

exit(0);
