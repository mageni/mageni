# Copyright (C) 2020 Greenbone Networks GmbH
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

CPE = "cpe:/a:adobe:indesign_server";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.817295");
  script_version("2020-09-11T10:38:07+0000");
  script_cve_id("CVE-2020-9727", "CVE-2020-9728", "CVE-2020-9729", "CVE-2020-9730",
                "CVE-2020-9731");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-09-14 09:56:38 +0000 (Mon, 14 Sep 2020)");
  script_tag(name:"creation_date", value:"2020-09-10 12:31:10 +0530 (Thu, 10 Sep 2020)");
  script_name("Adobe InDesign Security Updates (apsb20-52)-Windows");

  script_tag(name:"summary", value:"The host is installed with Adobe InDesign
  and is prone to multiple vulnerabilities");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Multiple memory corruption error.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code on the system.");

  script_tag(name:"affected", value:"Adobe InDesign 15.1.1 and earlier versions on Windows.");

  script_tag(name:"solution", value:"Upgrade to Adobe InDesign 15.1.2 or later. Please
  see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/indesign/apsb20-52.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_adobe_indesign_detect.nasl");
  script_mandatory_keys("Adobe/InDesign/Ver");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE )) exit(0);
vers = infos['version'];
path = infos['location'];

if(version_is_less(version:vers, test_version:"15.1.2"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"15.1.2", install_path:path);
  security_message(data:report);
  exit(0);
}
exit(99);
