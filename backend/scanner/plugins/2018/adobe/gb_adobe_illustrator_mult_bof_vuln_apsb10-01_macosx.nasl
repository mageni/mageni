###############################################################################
# OpenVAS Vulnerability Test
#
# Adobe Illustrator Multiple Buffer Overflow Vulnerabilities-Mac OS X (apsb10-01)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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

CPE = "cpe:/a:adobe:illustrator";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813494");
  script_version("2019-05-17T10:45:27+0000");
  script_cve_id("CVE-2009-3952", "CVE-2009-4195");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2018-07-12 15:35:32 +0530 (Thu, 12 Jul 2018)");
  script_tag(name:"qod", value:"30"); ## Solution is Mitigation
  script_name("Adobe Illustrator Multiple Buffer Overflow Vulnerabilities-Mac OS X (apsb10-01)");

  script_tag(name:"summary", value:"The host is installed with Adobe Illustrator
  and is prone to multiple buffer overflow vulnerabilities..");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - An error where a specially crafted EPS file once loaded by the target user
    triggers a buffer overflow error.

  - An unspecified error leading to buffer overflow error.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code on the affected system.");

  script_tag(name:"affected", value:"Adobe Illustrator CS4 version 14.0.0 and Adobe
  Illustrator CS3 versions 13.0.3 and earlier on Mac OS X.");

  script_tag(name:"solution", value:"Patch is available as a solution from
  vendor. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.adobe.com/support/security/bulletins/apsb10-01.html");
  script_xref(name:"URL", value:"https://www.adobe.com");

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_adobe_illustrator_detect_macosx.nasl");
  script_mandatory_keys("Adobe/Illustrator/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE )) exit(0);
adobeVer = infos['version'];
adobePath = infos['location'];

if(version_is_less_equal(version:adobeVer, test_version:"13.0.3")||
   version_is_equal(version:adobeVer, test_version:"14.0.0"))
{
  report = report_fixed_ver(installed_version:adobeVer, fixed_version:'Apply Mitigation', install_path:adobePath);
  security_message(data: report);
  exit(0);
}
exit(0);
