###############################################################################
# OpenVAS Vulnerability Test
#
# Adobe Dreamweaver Command Injection Vulnerability Mar18 (Windows)
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

CPE = "cpe:/a:adobe:dreamweaver";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813039");
  script_version("2019-05-17T10:45:27+0000");
  script_cve_id("CVE-2018-4924");
  script_bugtraq_id(103395);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2018-03-15 11:20:29 +0530 (Thu, 15 Mar 2018)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Adobe Dreamweaver Command Injection Vulnerability Mar18 (Windows)");

  script_tag(name:"summary", value:"The host is installed with Adobe Dreamweaver
  and is prone to a command injection vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an improper
  sanitization of user supplied input.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  to execute arbitrary code in the context of the current user. Failed exploit
  attempts may result in a denial of service condition.");

  script_tag(name:"affected", value:"Adobe Dreamweaver CC 18.0 and earlier versions on Windows.");

  script_tag(name:"solution", value:"Upgrade to Adobe Dreamweaver CC 18.1 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/dreamweaver/apsb18-07.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_adobe_dreamweaver_detect.nasl");
  script_mandatory_keys("Adobe/Dreamweaver/Ver");
  script_xref(name:"URL", value:"http://www.adobe.com");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
drVer = infos['version'];
drPath = infos['location'];

if(version_is_less(version:drVer, test_version:"18.1"))
{
  report = report_fixed_ver(installed_version:drVer, fixed_version:"18.1", install_path:drPath);
  security_message(data:report);
  exit(0);
}
exit(0);
