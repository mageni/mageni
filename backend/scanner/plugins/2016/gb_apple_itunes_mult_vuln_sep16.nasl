###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apple_itunes_mult_vuln_sep16.nasl 12051 2018-10-24 09:14:54Z asteins $
#
# Apple iTunes Multiple Vulnerabilities Sep16 (Windows)
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
CPE = "cpe:/a:apple:itunes";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807890");
  script_version("$Revision: 12051 $");
  script_cve_id("CVE-2016-4728", "CVE-2016-4758", "CVE-2016-4759", "CVE-2016-4762",
                "CVE-2016-4766", "CVE-2016-4767", "CVE-2016-4768", "CVE-2016-4760",
                "CVE-2016-4765", "CVE-2016-4763", "CVE-2016-4769");
  script_bugtraq_id(93064, 93066, 93067, 93062);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-24 11:14:54 +0200 (Wed, 24 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-09-28 15:03:42 +0530 (Wed, 28 Sep 2016)");
  script_name("Apple iTunes Multiple Vulnerabilities Sep16 (Windows)");

  script_tag(name:"summary", value:"This host is installed with Apple iTunes
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - A parsing issue in the handling of error prototypes.

  - A permissions issue in the handling of the location variable.

  - Multiple memory corruption issues.

  - Cross-protocol exploitation of non-HTTP services using DNS rebinding.

  - A certificate validation issue in the handling of WKWebView.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code, intercept and alter network traffic, access
  non-HTTP services and gain access to potentially sensitive information.");

  script_tag(name:"affected", value:"Apple iTunes versions before 12.5.1
  on Windows.");

  script_tag(name:"solution", value:"Upgrade to Apple iTunes 12.5.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT207158");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
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
if(version_is_less(version:ituneVer, test_version:"12.5.1"))
{
  report = report_fixed_ver(installed_version:ituneVer, fixed_version:"12.5.1");
  security_message(data:report);
  exit(0);
}
