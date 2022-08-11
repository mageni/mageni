###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_photoshop_mult_vuln_feb16.nasl 12455 2018-11-21 09:17:27Z cfischer $
#
# Adobe Photoshop CC Multiple Vulnerabilities (Windows)
#
# Authors:
# Kashianth T <tkashinath@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:adobe:photoshop_cc2015";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806869");
  script_version("$Revision: 12455 $");
  script_cve_id("CVE-2016-0951", "CVE-2016-0952", "CVE-2016-0953");
  script_bugtraq_id(83114);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-11-21 10:17:27 +0100 (Wed, 21 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-02-15 13:37:52 +0530 (Mon, 15 Feb 2016)");
  script_name("Adobe Photoshop CC Multiple Vulnerabilities (Windows)");

  script_tag(name:"summary", value:"The host is installed with Adobe Photoshop
  CC and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to
  multiple memory corruption vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code or cause a denial of service
  (memory corruption) via unspecified vectors.");

  script_tag(name:"affected", value:"Adobe Photoshop CC 2014 before 15.2.4,
  Photoshop CC 2015 before 16.1.2 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Adobe Photoshop CC version
  16.1.2 (2015.1.2) or 15.2.4 (2014.2.4) or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/photoshop/apsb16-03.html");

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_adobe_photoshop_detect.nasl");
  script_mandatory_keys("Adobe/Photoshop/Installed");
  script_xref(name:"URL", value:"http://www.adobe.com/in/products/photoshop.html");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!prodVer = get_app_version(cpe:CPE))
{
  CPE = "cpe:/a:adobe:photoshop_cc2014";
  if(!prodVer = get_app_version(cpe:CPE)){
    exit(0);
  }
}

if(version_is_less(version:prodVer, test_version:"16.1.2"))
{
  fix = "16.1.2 (2015.1.2)";
}
else if(version_is_less(version:prodVer, test_version:"15.2.4"))
{
  fix = "15.2.4 (2014.2.4)";
}

if(fix)
{
  report = report_fixed_ver(installed_version:prodVer, fixed_version:fix);
  security_message(data:report);
  exit(0);
}
