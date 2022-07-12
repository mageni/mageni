###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_trend_micro_wfbs_mult_vuln.nasl 12051 2018-10-24 09:14:54Z asteins $
#
# Trend Micro WFBS Multiple Vulnerabilities
#
# Authors:
# Tushar Khelge <tushar.khelge@secpod.com>
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

CPE = "cpe:/a:trend_micro:business_security";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809143");
  script_version("$Revision: 12051 $");
  script_cve_id("CVE-2016-1223", "CVE-2016-1224");
  script_bugtraq_id(91288, 91290);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-24 11:14:54 +0200 (Wed, 24 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-08-23 12:01:39 +0530 (Tue, 23 Aug 2016)");
  script_name("Trend Micro WFBS Multiple Vulnerabilities");

  script_tag(name:"summary", value:"This host is installed with Trend
  Micro Worry-Free Business Security and is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to the
  unintended file could be accessed and potential unintended script may
  gets executed.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to cause path traversal and HTTP header injection Vulnerability and to inject
  arbitrary HTTP headers and conduct cross-site scripting (XSS).");

  script_tag(name:"affected", value:"Trend Micro Worry-Free Business Security
  versions prior to 9.0.0.4259.");

  script_tag(name:"solution", value:"Upgrade to Trend Micro Worry-Free Business
  Security 9.0 Service Pack 3 (build 4259).");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"http://esupport.trendmicro.com/solution/ja-JP/1114102.aspx");
  script_xref(name:"URL", value:"http://jvn.jp/en/jp/JVN48847535/index.html");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_trend_micro_worry_free_business_security_detect.nasl");
  script_mandatory_keys("Trend/Micro/Worry-Free/Business/Security/Ver");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!trendVer = get_app_version(cpe:CPE)){
  exit(0);
}

##http://esupport.trendmicro.com/solution/ja-JP/1114173.aspx
if(trendVer =~ "^9\.")
{
  if(version_is_less(version:trendVer, test_version:"9.0.0.4259"))
  {
    report = report_fixed_ver(installed_version:trendVer, fixed_version:"9.0.0.4259");
    security_message(data:report);
    exit(0);
  }
}
