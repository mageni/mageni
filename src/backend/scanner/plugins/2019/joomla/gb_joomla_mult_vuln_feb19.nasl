# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) of the respective author(s)
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

CPE = "cpe:/a:joomla:joomla";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141991");
  script_version("2019-05-17T10:45:27+0000");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2019-02-13 09:32:39 +0700 (Wed, 13 Feb 2019)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2019-7739", "CVE-2019-7740", "CVE-2019-7741", "CVE-2019-7742", "CVE-2019-7743",
                "CVE-2019-7744");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Joomla! < 3.9.3 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_mandatory_keys("joomla/installed");

  script_tag(name:"summary", value:"Joomla! is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Joomla! is prone to multiple vulnerabilities:

  - The 'No Filtering' textfilter overrides child settings in the Global Configuration. (CVE-2019-7739)

  - Inadequate parameter handling in JavaScript code (core.js writeDynaList) could lead to an XSS attack vector.
    (CVE-2019-7740)

  - Inadequate checks at the Global Configuration helpurl settings allowed stored XSS. (CVE-2019-7741)

  - A combination of specific web server configurations, in connection with specific file types and browser-side
    MIME-type sniffing, causes an XSS attack vector. (CVE-2019-7742)

  - The phar:// stream wrapper can be used for objection injection attacks because there is no protection
    mechanism (such as the TYPO3 PHAR stream wrapper) to prevent use of the phar:// handler for non .phar-files.
    (CVE-2019-7743)

  - Inadequate filtering on URL fields in various core components could lead to an XSS vulnerability.
    (CVE-2019-7744)");

  script_tag(name:"affected", value:"Joomla! CMS versions 2.5.0 through 3.9.2.");

  script_tag(name:"solution", value:"Update to version 3.9.3 or later.");

  script_xref(name:"URL", value:"https://developer.joomla.org/security-centre/767-20190203-core-additional-warning-in-the-global-configuration-textfilter-settings");
  script_xref(name:"URL", value:"https://developer.joomla.org/security-centre/769-20190205-core-xss-issue-in-core-js-writedynalist");
  script_xref(name:"URL", value:"https://developer.joomla.org/security-centre/768-20190204-core-stored-xss-issue-in-the-global-configuration-help-url-2");
  script_xref(name:"URL", value:"https://developer.joomla.org/security-centre/766-20190202-core-browserside-mime-type-sniffing-causes-xss-attack-vectors");
  script_xref(name:"URL", value:"https://developer.joomla.org/security-centre/770-20190206-core-implement-the-typo3-phar-stream-wrapper");
  script_xref(name:"URL", value:"https://developer.joomla.org/security-centre/765-20190201-core-lack-of-url-filtering-in-various-core-components");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if(!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE)) exit(0);
version = infos['version'];
path = infos['location'];

if (version_in_range(version: version, test_version: "2.5.0", test_version2: "3.9.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.9.3", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
