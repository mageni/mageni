###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_creative_cloud_apsb17-13_win.nasl 12391 2018-11-16 16:12:15Z cfischer $
#
# Adobe Creative Cloud Security Updates APSB17-13 (Windows)
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

CPE = "cpe:/a:adobe:creative_cloud";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811018");
  script_version("$Revision: 12391 $");
  script_cve_id("CVE-2017-3006", "CVE-2017-3007");
  script_bugtraq_id(97555, 97558);
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 17:12:15 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2017-05-04 12:14:45 +0530 (Thu, 04 May 2017)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Adobe Creative Cloud Security Updates APSB17-13 (Windows)");

  script_tag(name:"summary", value:"This host is installed with Adobe Creative
  cloud and is prone to security bypass and remote code execution vulnerabilities");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - The use of improper resource permissions during the installation of Creative
    Cloud desktop applications.

  - An error related to the directory search path used to find resources.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to gain elevated privileges and leads to code execution.
  Failed exploit attempts will likely cause a denial-of-service condition.");

  script_tag(name:"affected", value:"Adobe Creative Cloud before 4.0.0.185
  on Windows.");

  script_tag(name:"solution", value:"Upgrade to Adobe Creative Cloud version
  4.0.0.185 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/creative-cloud/apsb17-13.html");
  script_xref(name:"URL", value:"http://hyp3rlinx.altervista.org/advisories/ADOBE-CREATIVE-CLOUD-PRIVILEGE-ESCALATION.txt");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_adobe_creative_cloud_detect_win.nasl");
  script_mandatory_keys("AdobeCreativeCloud/Win/Ver");
  script_xref(name:"URL", value:"https://www.adobe.com/creativecloud/desktop-app.html");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!cloudVer = get_app_version(cpe:CPE, nofork: TRUE)){
  exit(0);
}

if(version_is_less(version:cloudVer, test_version:"4.0.0.185"))
{
  report = report_fixed_ver(installed_version:cloudVer, fixed_version:"4.0.0.185");
  security_message(data:report);
  exit(0);
}
