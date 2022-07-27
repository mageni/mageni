###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_reader_mult_vuln_mar16_win.nasl 11922 2018-10-16 10:24:25Z asteins $
#
# Adobe Reader Multiple Vulnerabilities March16 (Windows)
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

CPE = "cpe:/a:adobe:acrobat_reader";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807471");
  script_version("$Revision: 11922 $");
  script_cve_id("CVE-2016-1007", "CVE-2016-1008", "CVE-2016-1009");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-16 12:24:25 +0200 (Tue, 16 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-03-10 11:12:19 +0530 (Thu, 10 Mar 2016)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Adobe Reader Multiple Vulnerabilities March16 (Windows)");

  script_tag(name:"summary", value:"This host is installed with Adobe Reader
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to

  - Some memory leak vulnerabilities.

  - An untrusted search path vulnerability in Adobe Download Manager");

  script_tag(name:"impact", value:"Successful exploitation will allow
  remote attackers to execute arbitrary code.");

  script_tag(name:"affected", value:"Adobe Reader 11.x before 11.0.15 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Adobe Reader version 11.0.15
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/acrobat/apsb16-09.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_win.nasl");
  script_mandatory_keys("Adobe/Reader/Win/Installed");
  script_xref(name:"URL", value:"http://www.adobe.com/");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!readerVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_in_range(version:readerVer, test_version:"11.0.0", test_version2:"11.0.14"))
{
  report = report_fixed_ver(installed_version:readerVer, fixed_version:"11.0.15");
  security_message(data:report);
  exit(0);
}
