###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apple_quicktime_mult_rce_vuln_apr16_win.nasl 11969 2018-10-18 14:53:42Z asteins $
#
# Apple QuickTime Multiple Remote Code Execution Vulnerabilities Apr16 (Windows)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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

CPE = "cpe:/a:apple:quicktime";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807545");
  script_version("$Revision: 11969 $");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-18 16:53:42 +0200 (Thu, 18 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-04-18 12:07:38 +0530 (Mon, 18 Apr 2016)");
  script_name("Apple QuickTime Multiple Remote Code Execution Vulnerabilities Apr16 (Windows)");

  script_tag(name:"summary", value:"This host is installed with Apple QuickTime
  and is prone to multiple remote code execution vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - A heap buffer overflow vulnerability in the 'moov atom'.

  - A heap buffer overfolw vulnerability in the 'atom processing'.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code under the context of the QuickTime player.");

  script_tag(name:"affected", value:"Apple QuickTime version 7.7.9 and earlier
  on Windows.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the
  disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade
  to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT205771");
  script_xref(name:"URL", value:"http://zerodayinitiative.com/advisories/ZDI-16-241");
  script_xref(name:"URL", value:"http://zerodayinitiative.com/advisories/ZDI-16-242");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_apple_quicktime_detection_win_900124.nasl");
  script_mandatory_keys("QuickTime/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!quickVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less_equal(version:quickVer, test_version:"7.79.80.95"))
{
  report = report_fixed_ver(installed_version:quickVer, fixed_version:"Uninstall Apple QuickTime");
  security_message(data:report);
  exit(0);
}
