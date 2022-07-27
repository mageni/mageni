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

CPE = "cpe:/a:plone:plone";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.146022");
  script_version("2021-05-27T02:49:06+0000");
  script_tag(name:"last_modification", value:"2021-05-27 10:33:26 +0000 (Thu, 27 May 2021)");
  script_tag(name:"creation_date", value:"2021-05-27 02:26:31 +0000 (Thu, 27 May 2021)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");

  script_cve_id("CVE-2021-3313", "CVE-2021-21360", "CVE-2021-21336", "CVE-2021-32633", "CVE-2021-33507",
                "CVE-2021-33508", "CVE-2021-33509", "CVE-2021-33510", "CVE-2021-33511", "CVE-2021-33512",
                "CVE-2021-33513");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Plone <= 5.2.4 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_plone_detect.nasl");
  script_mandatory_keys("plone/installed");

  script_tag(name:"summary", value:"Plone is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2021-3313, CVE-2021-33508: Stored XSS from user fullname

  - CVE-2021-21360, CVE-2021-21336: Various information disclosures

  - CVE-2021-32633: Remote Code Execution via traversal in expressions

  - CVE-2021-33507: Reflected XSS in various spots

  - CVE-2021-33509: Writing arbitrary files via docutils and Python Script

  - CVE-2021-33510: Server Side Request Forgery via event ical URL

  - CVE-2021-33511: Server Side Request Forgery via lxml parser

  - CVE-2021-33512: Reflected XSS in various spots

  - CVE-2021-33513: Stored XSS from user fullname");

  script_tag(name:"affected", value:"Plone through version 5.2.4.");

  script_tag(name:"solution", value:"Install the provided Hotfix.");

  script_xref(name:"URL", value:"https://plone.org/security/hotfix/20210518");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2021/05/22/1");
  script_xref(name:"URL", value:"https://www.compass-security.com/fileadmin/Research/Advisories/2021-07_CSNC-2021-013_XSS_in_Plone_CMS.txt");
  script_xref(name:"URL", value:"https://plone.org/security/hotfix/20210518/writing-arbitrary-files-via-docutils-and-python-script");
  script_xref(name:"URL", value:"https://plone.org/security/hotfix/20210518/server-side-request-forgery-via-event-ical-url");
  script_xref(name:"URL", value:"https://plone.org/security/hotfix/20210518/stored-xss-from-file-upload-svg-html");
  script_xref(name:"URL", value:"https://plone.org/security/hotfix/20210518/server-side-request-forgery-via-lxml-parser");
  script_xref(name:"URL", value:"https://plone.org/security/hotfix/20210518/xss-vulnerability-in-cmfdifftool");
  script_xref(name:"URL", value:"https://plone.org/security/hotfix/20210518/stored-xss-from-user-fullname");

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

if (version_is_less_equal(version: version, test_version: "5.2.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "Apply Hotfix", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
