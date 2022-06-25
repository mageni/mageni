###############################################################################
# OpenVAS Vulnerability Test
#
# Adobe Photoshop CC Multiple Memory Corruption Vulnerabilities - APSB18-28 (Mac OS X)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation;
# either version 2 of the License, or (at your option) any later version.
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

CPE = "cpe:/a:adobe:photoshop_cc2017";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813871");
  script_version("2019-05-03T08:55:39+0000");
  script_cve_id("CVE-2018-12810", "CVE-2018-12811");
  script_bugtraq_id(105123);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-05-03 08:55:39 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2018-08-23 11:02:24 +0530 (Thu, 23 Aug 2018)");
  script_name("Adobe Photoshop CC Multiple Memory Corruption Vulnerabilities - APSB18-28 (Mac OS X)");

  script_tag(name:"summary", value:"The host is installed with Adobe Photoshop
  CC and is prone to multiple memory corruption vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to multiple
  unspecified memory corruption vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to execute arbitrary code in the context of the user running the affected
  application. Failed exploit attempts will likely result in denial-of-service
  conditions.");

  script_tag(name:"affected", value:"Adobe Photoshop CC 2017 18.1.5 and earlier
  and Adobe Photoshop CC 2018 19.1.5 and earlier versions on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to Adobe Photoshop CC 2017
  18.1.6 or Photoshop CC 2018 19.1.6 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/photoshop/apsb18-28.html");
  script_xref(name:"URL", value:"http://www.adobe.com/in/products/photoshop.html");

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_adobe_photoshop_detect_macosx.nasl");
  script_mandatory_keys("Adobe/Photoshop/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE ))
{
  CPE = "cpe:/a:adobe:photoshop_cc2018";
  infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE);
}

pver = infos['version'];
ppath = infos['location'];
if (pver =~ "^18\..*")
{
  if(version_is_less_equal(version:pver, test_version:"18.1.5"))
   {
     fix = "18.1.6";
     installed_ver = "Adobe Photoshop CC 2017";
   }
}

else if (pver =~ "^19\..*")
{
  if(version_is_less_equal(version:pver, test_version:"19.1.5"))
   {
     fix = "19.1.6";
     installed_ver = "Adobe Photoshop CC 2018";
   }
}

if(fix)
{
  report = report_fixed_ver( installed_version: installed_ver + " " + pver, fixed_version: fix, install_path:ppath );
  security_message(data:report);
}
exit(0);
