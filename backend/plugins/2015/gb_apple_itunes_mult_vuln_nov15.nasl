###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apple_itunes_mult_vuln_nov15.nasl 11872 2018-10-12 11:22:41Z cfischer $
#
# Apple iTunes Multiple Vulnerabilities Nov15 (Windows)
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

CPE = "cpe:/a:apple:itunes";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806609");
  script_version("$Revision: 11872 $");
  script_cve_id("CVE-2015-5928", "CVE-2015-5929", "CVE-2015-5930", "CVE-2015-5931",
                "CVE-2015-7002", "CVE-2015-7011", "CVE-2015-7012", "CVE-2015-7013",
                "CVE-2015-7014", "CVE-2015-6975", "CVE-2015-6992", "CVE-2015-7017");
  script_bugtraq_id(77264, 77267, 77270);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:22:41 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-11-03 14:51:27 +0530 (Tue, 03 Nov 2015)");
  script_name("Apple iTunes Multiple Vulnerabilities Nov15 (Windows)");

  script_tag(name:"summary", value:"This host is installed with Apple iTunes
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - Multiple memory corruption issues in WebKit.

  - Multiple memory corruption issues in the processing of text files.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code or conduct denial-of-service condition on
  the affected system.");

  script_tag(name:"affected", value:"Apple iTunes versions before 12.3.1
  on Windows.");

  script_tag(name:"solution", value:"Upgrade to Apple iTunes 12.3.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT205372");
  script_xref(name:"URL", value:"http://lists.apple.com/archives/security-announce/2015/Oct/msg00006.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_apple_itunes_detection_win_900123.nasl");
  script_mandatory_keys("iTunes/Win/Installed");
  script_xref(name:"URL", value:"http://www.apple.com/itunes");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!ituneVer = get_app_version(cpe:CPE)){
  exit(0);
}

##  Check for Apple iTunes vulnerable versions
if(version_is_less(version:ituneVer, test_version:"12.3.1"))
{
  report = 'Installed version: ' + ituneVer + '\n' +
           'Fixed version:     12.3.1 \n';
  security_message(data:report);
  exit(0);
}
