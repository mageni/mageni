###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_creative_cloud_apsb16-34_win.nasl 12391 2018-11-16 16:12:15Z cfischer $
#
# Adobe Creative Cloud Security Update APSB16-34 (Windows)
#
# Authors:
# Tushar Khelge <ktushar@secpod.com>
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

CPE = "cpe:/a:adobe:creative_cloud";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809450");
  script_version("$Revision: 12391 $");
  script_cve_id("CVE-2016-6935");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 17:12:15 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-10-13 15:55:28 +0530 (Thu, 13 Oct 2016)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Adobe Creative Cloud Security Update APSB16-34 (Windows)");

  script_tag(name:"summary", value:"This host is installed with Adobe Creative
  cloud and is prone to local privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an unquoted service
  path enumeration vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation will allow local
  users to gain privileges of the system thereby leading to further attcks.");

  script_tag(name:"affected", value:"Adobe Creative Cloud before 3.8.0.310
  on Windows.");

  script_tag(name:"solution", value:"Upgrade to Adobe Creative Cloud version
  3.8.0.310 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/creative-cloud/apsb16-34.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_adobe_creative_cloud_detect_win.nasl");
  script_mandatory_keys("AdobeCreativeCloud/Win/Ver");
  script_xref(name:"URL", value:"https://www.adobe.com/creativecloud/desktop-app.html");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!cloudVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:cloudVer, test_version:"3.8.0.310"))
{
  report = report_fixed_ver(installed_version:cloudVer, fixed_version:"3.8.0.310");
  security_message(data:report);
  exit(0);
}
