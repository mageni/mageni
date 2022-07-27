###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_symantec_endpoint_protection_mult_vuln_july16.nasl 12149 2018-10-29 10:48:30Z asteins $
#
# Symantec Endpoint Protection Multiple Vulnerabilities- July16
#
# Authors:
# Tushar Khelge <ktushar@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:symantec:endpoint_protection";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808510");
  script_version("$Revision: 12149 $");
  script_cve_id("CVE-2016-2207", "CVE-2016-2209", "CVE-2016-2210", "CVE-2016-2211",
                "CVE-2016-3644", "CVE-2016-3645", "CVE-2016-3646", "CVE-2016-3647",
                "CVE-2016-3648", "CVE-2016-3649", "CVE-2016-3650", "CVE-2016-3651",
                "CVE-2016-3652", "CVE-2016-3653", "CVE-2016-5304", "CVE-2016-5305",
                "CVE-2016-5306", "CVE-2016-5307", "CVE-2015-8801", "CVE-2016-5309",
                "CVE-2016-5310");
  script_bugtraq_id(91434, 91436, 91437, 91438, 91431, 91439, 91435, 91433, 91441,
                    91440, 91432, 91445, 91444, 91442, 91447, 91448, 91449, 91443,
                    91446, 92866, 92868);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-29 11:48:30 +0100 (Mon, 29 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-07-04 14:15:06 +0530 (Mon, 04 Jul 2016)");
  script_name("Symantec Endpoint Protection Multiple Vulnerabilities- July16");

  script_tag(name:"summary", value:"This host is installed with Symantec
  Endpoint Protection and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - An error in parsing of maliciously-formatted container files in symantecs
    decomposer engine.

  - An improper validation in the management console.

  - The mishandling of RAR file by RAR file parser component in the AntiVirus
    Decomposer engine.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to cause memory corruption, integer overflow or buffer overflow results in an
  application-level denial of service and arbitrary code execution or to elevate
  privilege or gain access to unauthorized information on the management server.");

  script_tag(name:"affected", value:"Symantec Endpoint Protection (SEP)
  12.1.6 MP4 and prior.");

  script_tag(name:"solution", value:"Update to Symantec Endpoint Protection (SEP)
  version SEP 12.1 RU6 MP5 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=&suid=20160628_00");
  script_xref(name:"URL", value:"https://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=&suid=20160628_01");

  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("secpod_symantec_prdts_detect.nasl");
  script_mandatory_keys("Symantec/Endpoint/Protection");
  script_xref(name:"URL", value:"https://support.symantec.com/en_US/article.TECH103088.html");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!sepVer = get_app_version(cpe:CPE)){
  exit(0);
}

## http://www.symantec.com/connect/articles/sepm-1216-mp4-has-been-released-includes-win10-fixes
## https://support.symantec.com/en_US/article.TECH231877.html
if(sepVer =~ "^12\.1")
{
  if(version_is_less(version:sepVer, test_version:"12.1.7004.6500"))
  {
    report = report_fixed_ver(installed_version:sepVer, fixed_version:"12.1.7004.6500");
    security_message(data:report);
    exit(0);
  }
}
