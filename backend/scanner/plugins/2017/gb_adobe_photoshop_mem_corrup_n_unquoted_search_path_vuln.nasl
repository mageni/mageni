###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_photoshop_mem_corrup_n_unquoted_search_path_vuln.nasl 11977 2018-10-19 07:28:56Z mmartin $
#
# Adobe Photoshop Memory Corruption and Unquoted Search Path Vulnerabilities (Windows)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:adobe:photoshop_cc2017";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811017");
  script_version("$Revision: 11977 $");
  script_cve_id("CVE-2017-3004", "CVE-2017-3005");
  script_bugtraq_id(97559, 97553);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 09:28:56 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-05-03 14:33:41 +0530 (Wed, 03 May 2017)");
  script_name("Adobe Photoshop Memory Corruption and Unquoted Search Path Vulnerabilities (Windows)");

  script_tag(name:"summary", value:"The host is installed with Adobe Photoshop
  CC and is prone to memory corruption and unquoted search path vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to a memory
  corruption error when parsing malicious PCX files and an unquoted search path
  error.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code in the context of the user running the
  affected application and gain elevated privileges.");

  script_tag(name:"affected", value:"Adobe Photoshop CC 2017 before 18.1
  and Adobe Photoshop CC 2015.5 before 17.0.2 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Adobe Photoshop CC 2017 18.1
  or Adobe Photoshop CC 2015.5 17.0.2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/photoshop/apsb17-12.html");

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_adobe_photoshop_detect.nasl");
  script_mandatory_keys("Adobe/Photoshop/Installed");
  script_xref(name:"URL", value:"http://www.adobe.com/in/products/photoshop.html");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!prodVer2017 = get_app_version(cpe:CPE))
{
  CPE = "cpe:/a:adobe:photoshop_cc2015.5";
  if(!prodVer2015 = get_app_version(cpe:CPE)){
    exit(0);
  }
}

if(prodVer2017 && version_is_less(version:prodVer2017, test_version:"18.1"))
{
  fix = "CC 2017 18.1";
  VULN = TRUE;
  prodVer = "CC 2017 " + prodVer2017;
}
else if(prodVer2015 && version_is_less(version:prodVer2015, test_version:"17.0.2"))
{
  fix = "CC 2015.5 17.0.2 (2015.5.2)";
  VULN = TRUE;
  prodVer = "CC 2015.5 " + prodVer2015;
}

if(VULN)
{
  report = report_fixed_ver(installed_version:prodVer, fixed_version:fix);
  security_message(data:report);
  exit(0);
}
