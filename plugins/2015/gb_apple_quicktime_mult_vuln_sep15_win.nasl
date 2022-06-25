###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apple_quicktime_mult_vuln_sep15_win.nasl 11872 2018-10-12 11:22:41Z cfischer $
#
# Apple QuickTime Multiple Vulnerabilities Sep15 (Windows)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.805969");
  script_version("$Revision: 11872 $");
  script_cve_id("CVE-2015-3788", "CVE-2015-3789", "CVE-2015-3790", "CVE-2015-3791",
                "CVE-2015-3792", "CVE-2015-5751", "CVE-2015-5779", "CVE-2015-5785",
                "CVE-2015-5786");
  script_bugtraq_id(76340, 76443, 76444);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:22:41 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-09-01 17:24:20 +0530 (Tue, 01 Sep 2015)");
  script_name("Apple QuickTime Multiple Vulnerabilities Sep15 (Windows)");

  script_tag(name:"summary", value:"This host is installed with Apple QuickTime
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to multiple memory
  corruption issues.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to have unexpected application termination or arbitrary code execution.");

  script_tag(name:"affected", value:"Apple QuickTime version before 7.7.8 on
  Windows.");

  script_tag(name:"solution", value:"Upgrade to Apple QuickTime version 7.7.8
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"http://lists.apple.com/archives/security-announce/2015/Aug/msg00004.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_apple_quicktime_detection_win_900124.nasl");
  script_mandatory_keys("QuickTime/Win/Ver");
  script_xref(name:"URL", value:"http://support.apple.com/downloads");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!quickVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:quickVer, test_version:"7.78.80.95"))
{
  report = 'Installed version: ' + quickVer + '\n' +
           'Fixed version:     ' + "7.78.80.95" + '\n';
  security_message(port:0, data:report);
  exit(0);
}
