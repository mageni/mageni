# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
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

CPE = "cpe:/a:adobe:photoshop_cc2018";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.815540");
  script_version("2019-08-14T14:30:23+0000");
  script_cve_id("CVE-2019-7968", "CVE-2019-7969", "CVE-2019-7970", "CVE-2019-7971",
                "CVE-2019-7972", "CVE-2019-7973", "CVE-2019-7974", "CVE-2019-7975",
                "CVE-2019-7976", "CVE-2019-7977", "CVE-2019-7978", "CVE-2019-7979",
                "CVE-2019-7980", "CVE-2019-7981", "CVE-2019-7982", "CVE-2019-7983",
                "CVE-2019-7984", "CVE-2019-7985", "CVE-2019-7986", "CVE-2019-7987",
                "CVE-2019-7988", "CVE-2019-7989", "CVE-2019-7990", "CVE-2019-7991",
                "CVE-2019-7992", "CVE-2019-7993", "CVE-2019-7994", "CVE-2019-7995",
                "CVE-2019-7996", "CVE-2019-7997", "CVE-2019-7998", "CVE-2019-7999",
                "CVE-2019-8000", "CVE-2019-8001");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-08-14 14:30:23 +0000 (Wed, 14 Aug 2019)");
  script_tag(name:"creation_date", value:"2019-08-14 17:14:11 +0530 (Wed, 14 Aug 2019)");
  script_name("Adobe Photoshop CC Multiple Vulnerabilities August19 (Windows)");

  script_tag(name:"summary", value:"The host is installed with Adobe Photoshop
  CC and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on
  the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - Heap overflow errors,

  - Type confusion errors,

  - Out of bound read errors,

  - Command injection errors and

  - Out of bound write errors.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code in the context of the application and
  leak the memory.");

  script_tag(name:"affected", value:"Adobe Photoshop CC 2018 19.1.8 and earlier
  and Adobe Photoshop CC 2019 20.0.5 and earlier versions on Windows.");

  script_tag(name:"solution", value:"Upgrade to Adobe Photoshop CC 2018 19.1.9
  or Photoshop CC 2019 20.0.6 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/photoshop/apsb19-44.html");
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_adobe_photoshop_detect.nasl");
  script_mandatory_keys("Adobe/Photoshop/Installed");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE ))
{
  CPE = "cpe:/a:adobe:photoshop_cc2019";
  infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE);
}

if(!pver = infos['version']){
  exit(0);
}
ppath = infos['location'];

if (pver =~ "^19\.")
{
  if(version_is_less_equal(version:pver, test_version:"19.1.8"))
  {
    fix = "19.1.9";
    installed_ver = "Adobe Photoshop CC 2018";
  }
}

else if (pver =~ "^20\.")
{
  if(version_is_less_equal(version:pver, test_version:"20.0.5"))
  {
    fix = "20.0.6";
    installed_ver = "Adobe Photoshop CC 2019";
  }
}

if(fix)
{
  report = report_fixed_ver( installed_version: installed_ver + " " + pver, fixed_version: fix, install_path:ppath );
  security_message(data:report);
}
exit(99);
