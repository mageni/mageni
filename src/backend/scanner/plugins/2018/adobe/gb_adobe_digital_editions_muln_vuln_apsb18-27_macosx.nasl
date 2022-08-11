##############################################################################
# OpenVAS Vulnerability Test
#
# Adobe Digital Editions Mulptiple Vulnerabilities(APSB18-27)-Mac OS X
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:adobe:digital_editions";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814089");
  script_version("2019-05-17T10:45:27+0000");
  script_cve_id("CVE-2018-12814", "CVE-2018-12813", "CVE-2018-12823", "CVE-2018-12816",
                "CVE-2018-12818", "CVE-2018-12819", "CVE-2018-12820", "CVE-2018-12821",
                "CVE-2018-12822");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2018-10-11 10:35:08 +0530 (Thu, 11 Oct 2018)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Adobe Digital Editions Mulptiple Vulnerabilities(APSB18-27)-Mac OS X");

  script_tag(name:"summary", value:"This host is installed with Adobe Digital
  Edition and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to,

  - Multiple out-of-bounds read errors.

  - Multiple heap overflow errors.

  - An use after free error.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to gain conduct arbitrary code execution and information disclosure.");

  script_tag(name:"affected", value:"Adobe Digital Edition versions prior to 4.5.9 on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to Adobe Digital Edition version
  4.5.9 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://www.adobe.com/in/solutions/ebook/digital-editions/download.html");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/Digital-Editions/apsb18-27.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_adobe_digital_edition_detect_macosx.nasl");
  script_mandatory_keys("AdobeDigitalEdition/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
digitalVer = infos['version'];
digitalPath = infos['location'];

if(version_is_less(version:digitalVer, test_version:"4.5.9"))
{
  report = report_fixed_ver(installed_version:digitalVer, fixed_version:"4.5.9", install_path:digitalPath);
  security_message(data:report);
  exit(0);
}
exit(99);
