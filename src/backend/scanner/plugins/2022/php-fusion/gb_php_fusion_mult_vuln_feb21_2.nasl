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

CPE = "cpe:/a:php-fusion:php-fusion";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126269");
  script_version("2022-12-23T09:55:27+0000");
  script_tag(name:"last_modification", value:"2022-12-23 09:55:27 +0000 (Fri, 23 Dec 2022)");
  script_tag(name:"creation_date", value:"2022-12-22 10:22:35 +0000 (Thu, 22 Dec 2022)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:N");

  script_cve_id("CVE-2020-23181", "CVE-2020-23182", "CVE-2020-23184", "CVE-2020-23185",
                "CVE-2020-23702");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PHPFusion < 9.03.70 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_php_fusion_detect.nasl");
  script_mandatory_keys("php-fusion/detected");

  script_tag(name:"summary", value:"PHPFusion is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2020-23181: A reflected XSS vulnerability in /administration/theme.php

  - CVE-2020-23182: The component /php-fusion/infusions/shoutbox_panel/shoutbox_archive.php allows
  attackers to redirect victim users to malicious websites via a crafted payload entered into the
  Shoutbox message panel.

  - CVE-2020-23184: A stored XSS vulnerability in /administration/settings_registration.php

  - CVE-2020-23185: A stored XSS vulnerability in /administration/setting_security.php

  - CVE-2020-23702: XSS vulnerability via New Shout in /infusions/shoutbox_panel/shoutbox_admin.php");

  script_tag(name:"affected", value:"PHPFusion version 9.03.60 and probably prior.");

  script_tag(name:"solution", value:"Update to version 9.03.70 or later.");

  script_xref(name:"URL", value:"https://www.php-fusion.co.uk/infusions/news/news.php?readmore=647");
  script_xref(name:"URL", value:"https://github.com/phpfusion/PHPFusion/issues/2326");
  script_xref(name:"URL", value:"https://github.com/phpfusion/PHPFusion/issues/2329");
  script_xref(name:"URL", value:"https://github.com/phpfusion/PHPFusion/issues/2323");
  script_xref(name:"URL", value:"https://github.com/phpfusion/PHPFusion/issues/2331");
  script_xref(name:"URL", value:"https://github.com/phpfusion/PHPFusion/issues/2328");

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

if (version_is_less(version: version, test_version: "9.03.70")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.03.70", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
