###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_animate_memory_corruption_vuln_win.nasl 12313 2018-11-12 08:53:51Z asteins $
#
# Adobe Animate Memory Corruption Vulnerability-(Windows)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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

CPE = "cpe:/a:adobe:animate";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809769");
  script_version("$Revision: 12313 $");
  script_cve_id("CVE-2016-7866");
  script_bugtraq_id(94872);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-11-12 09:53:51 +0100 (Mon, 12 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-12-19 18:47:54 +0530 (Mon, 19 Dec 2016)");
  script_name("Adobe Animate Memory Corruption Vulnerability-(Windows)");

  script_tag(name:"summary", value:"This host is installed with Adobe Animate
  and is prone to memory corruption vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists when creating '.FLA' files
  with ActionScript Classes that use overly long Class names. This causes memory
  corruption leading to possible arbitrary code execution upon opening a maliciously
  created '.Fla' Flash file.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to
  run arbitrary code execution or conduct a denial of service condition.");

  script_tag(name:"affected", value:"Adobe Animate version 15.2.1.95 and earlier
  on Windows");

  script_tag(name:"solution", value:"Upgrade to Adobe Animate 16.0.0.112 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2016/Dec/45");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/animate/apsb16-38.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/539923/100/0/threaded");
  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/140164/Adobe-Animate-15.2.1.95-Buffer-Overflow.html");
  script_xref(name:"URL", value:"http://hyp3rlinx.altervista.org/advisories/ADOBE-ANIMATE-MEMORY-CORRUPTION-VULNERABILITY.txt");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_adobe_animate_detect_win.nasl");
  script_mandatory_keys("Adobe/Animate/Win/Ver");
  script_xref(name:"URL", value:"http://www.adobe.com/in/products/animate.html");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!adVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:adVer, test_version:"16.0.0.112"))
{
  report = report_fixed_ver(installed_version:adVer, fixed_version:"16.0.0.112");
  security_message(data:report);
  exit(0);
}
