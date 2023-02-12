# Copyright (C) 2023 Greenbone Networks GmbH
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

CPE = "cpe:/a:phpmyfaq:phpmyfaq";

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.126299");
  script_version("2023-01-17T10:10:58+0000");
  script_tag(name:"last_modification", value:"2023-01-17 10:10:58 +0000 (Tue, 17 Jan 2023)");
  script_tag(name:"creation_date", value:"2023-01-16 08:30:56 +0000 (Mon, 16 Jan 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2023-0306", "CVE-2023-0307", "CVE-2023-0308", "CVE-2023-0309",
                "CVE-2023-0310", "CVE-2023-0311", "CVE-2023-0312", "CVE-2023-0313",
                "CVE-2023-0314");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("phpmyFAQ < 3.1.10 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("phpmyfaq_detect.nasl");
  script_mandatory_keys("phpmyfaq/installed");

  script_tag(name:"summary", value:"phpMyFAQ is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist in GitHub repository
  thorsten/phpmyfaq:

  - CVE-2023-0306: Stored XSS in add new question

  - CVE-2023-0307: Weak password at demo website

  - CVE-2023-0308: Stored XSS in admin panel (users page)

  - CVE-2023-0309: Blind stored XSS in admin panel (open question page)

  - CVE-2023-0310: Stored XSS in FAQ comments

  - CVE-2023-0311: Bypass all captchas in the application

  - CVE-2023-0312: Blind stored XSS in administration panel

  - CVE-2023-0313: Stored XSS on user management, category, add new FAQ, add news and configuration

  - CVE-2023-0314: Reflected XSS which can help in any CSRF vulnerability");

  script_tag(name:"affected", value:"phpMyFAQ prior to version 3.1.10.");

  script_tag(name:"solution", value:"Update to version 3.1.10 or later.");

  script_xref(name:"URL", value:"https://huntr.dev/bounties/cbba22f0-89ed-4d01-81ea-744979c8cbde/");
  script_xref(name:"URL", value:"https://huntr.dev/bounties/fac01e9f-e3e5-4985-94ad-59a76485f215/");
  script_xref(name:"URL", value:"https://huntr.dev/bounties/83cfed62-af8b-4aaa-94f2-5a33dc0c2d69/");
  script_xref(name:"URL", value:"https://huntr.dev/bounties/c03c5925-43ff-450d-9827-2b65a3307ed6/");
  script_xref(name:"URL", value:"https://huntr.dev/bounties/051d5e20-7fab-4769-bd7d-d986b804bb5a/");
  script_xref(name:"URL", value:"https://huntr.dev/bounties/82b0b629-c56b-4651-af3f-17f749751857/");
  script_xref(name:"URL", value:"https://huntr.dev/bounties/f50ec8d1-cd60-4c2d-9ab8-3711870d83b9/");
  script_xref(name:"URL", value:"https://huntr.dev/bounties/bc27e84b-1f91-4e1b-a78c-944edeba8256/");
  script_xref(name:"URL", value:"https://huntr.dev/bounties/eac0a9d7-9721-4191-bef3-d43b0df59c67/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "3.1.10")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.1.10");
  security_message(data: report, port: port);
  exit(0);
}

exit(99);
