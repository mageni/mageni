###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apple_safari_mult_vuln_nov16.nasl 12391 2018-11-16 16:12:15Z cfischer $
#
# Apple Safari Multiple Vulnerabilities November16 (Mac OS X)
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

CPE = "cpe:/a:apple:safari";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810207");
  script_version("$Revision: 12391 $");
  script_cve_id("CVE-2016-1849", "CVE-2016-1858", "CVE-2016-1854", "CVE-2016-1855",
                "CVE-2016-1856", "CVE-2016-1857", "CVE-2016-1859");
  script_bugtraq_id(90690, 90689);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 17:12:15 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-11-22 11:05:47 +0530 (Tue, 22 Nov 2016)");
  script_name("Apple Safari Multiple Vulnerabilities November16 (Mac OS X)");

  script_tag(name:"summary", value:"This host is installed with Apple Safari
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - The 'Clear History and Website Data' feature mishandles the deletion of
    browsing history.

  - An insufficient taint tracking issue in the parsing of svg images.

  - Multiple memory corruption issues.");

  script_tag(name:"impact", value:"Successful exploitation will allow local
  attackers to obtain sensitive information, remote attackers to execute arbitrary
  code or cause a denial of service.");

  script_tag(name:"affected", value:"Apple Safari versions before 9.1.1");

  script_tag(name:"solution", value:"Upgrade to Apple Safari version 9.1.1 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT206565");
  script_xref(name:"URL", value:"http://lists.apple.com/archives/security-announce/2016/May/msg00005.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("macosx_safari_detect.nasl");
  script_mandatory_keys("AppleSafari/MacOSX/Version");
  script_xref(name:"URL", value:"http://www.apple.com/support");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!safVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:safVer, test_version:"9.1.1"))
{
  report = report_fixed_ver(installed_version:safVer, fixed_version:"9.1.1");
  security_message(data:report);
  exit(0);
}
