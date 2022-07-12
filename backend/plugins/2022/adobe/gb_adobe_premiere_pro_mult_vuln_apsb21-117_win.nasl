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
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA

CPE = "cpe:/a:adobe:premiere_pro";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.819908");
  script_version("2022-01-06T05:11:00+0000");
  script_cve_id("CVE-2021-43751", "CVE-2021-40790", "CVE-2021-40791", "CVE-2021-40795",
                "CVE-2021-42265");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-01-06 10:37:42 +0000 (Thu, 06 Jan 2022)");
  script_tag(name:"creation_date", value:"2022-01-03 08:25:27 +0530 (Mon, 03 Jan 2022)");
  script_name("Adobe Premiere Pro Multiple Vulnerabilities (APSB21-117) - Windows");

  script_tag(name:"summary", value:"Adobe Premiere Pro is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on
  the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - Multiple Out-of-bounds Read errors.

  - An Use After Free error.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to execute arbitrary code and escalate privileges on an affected system.");

  script_tag(name:"affected", value:"Adobe Premiere Pro versions 15.4.2 and prior, 22.0.");

  script_tag(name:"solution", value:"Update Adobe Premiere Pro to version 15.4.3
  or 22.1.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/premiere_pro/apsb21-117.html");

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_adobe_premiere_pro_detect_win.nasl");
  script_mandatory_keys("adobe/premierepro/win/detected");
  exit(0);
}
include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"15.4.3") ||
   vers == "22.0")
{
  report = report_fixed_ver(installed_version:vers, fixed_version:'15.4.3 or 22.1.1', install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
