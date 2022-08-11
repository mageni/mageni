###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_captivate_mult_vuln.nasl 11863 2018-10-12 09:42:02Z mmartin $
#
# Adobe Captivate Multiple Vulnerabilities (Windows)
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
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

CPE = "cpe:/a:adobe:captivate";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811136");
  script_version("$Revision: 11863 $");
  script_cve_id("CVE-2017-3087", "CVE-2017-3098");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 11:42:02 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-06-21 18:20:28 +0530 (Wed, 21 Jun 2017)");
  ##Qod is reduced to 30, due to hotfix provided cannot be detected.
  script_tag(name:"qod", value:"30");
  script_name("Adobe Captivate Multiple Vulnerabilities (Windows)");

  script_tag(name:"summary", value:"This host is installed with Adobe Captivate
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due an input validation
  error and secuirty bypass error in the quiz reporting feature.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code on the target system, escalate privileges
  and disclose sensitive information.");

  script_tag(name:"affected", value:"Adobe Captivate prior to 10.0.0.192
  on Windows.");

  script_tag(name:"solution", value:"Upgrade to Captivate version
  10.0.0.192 or later or apply hotfix for Adobe Captivate 8 and 9.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/captivate/apsb17-19.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_adobe_captivate_detect.nasl");
  script_mandatory_keys("Adobe/Captivate/Ver");
  script_xref(name:"URL", value:"http://www.adobe.com");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!digitalVer = get_app_version(cpe:CPE)){
  exit(0);
}

## 9 and earlier
if(version_is_less(version:digitalVer, test_version:"10.0.0.192"))
{
  report = report_fixed_ver(installed_version:digitalVer, fixed_version:"10.0.0.192");
  security_message(data:report);
  exit(0);
}
