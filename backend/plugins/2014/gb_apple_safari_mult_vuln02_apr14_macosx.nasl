###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apple_safari_mult_vuln02_apr14_macosx.nasl 14318 2019-03-19 11:44:05Z cfischer $
#
# Apple Safari Multiple Memory Corruption Vulnerabilities-02 Apr14 (Mac OS X)
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.804534");
  script_version("$Revision: 14318 $");
  script_cve_id("CVE-2014-1297", "CVE-2014-1298", "CVE-2014-1299", "CVE-2014-1301",
                "CVE-2014-1302", "CVE-2014-1304", "CVE-2014-1305", "CVE-2014-1307",
                "CVE-2014-1308", "CVE-2014-1309", "CVE-2014-1310", "CVE-2014-1311",
                "CVE-2014-1312", "CVE-2014-1313");
  script_bugtraq_id(66580, 66576, 66581, 66584, 66585, 66586, 66587,
                    66572, 66573, 66574, 66575, 66577, 66578, 66579);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 12:44:05 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2014-04-07 13:22:25 +0530 (Mon, 07 Apr 2014)");
  script_name("Apple Safari Multiple Memory Corruption Vulnerabilities-02 Apr14 (Mac OS X)");

  script_tag(name:"summary", value:"This host is installed with Apple Safari and is prone to multiple
  vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Flaws are due to muliple unspecified errors in the WebKit");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to bypass a sandbox protection
  mechanism, execute arbitrary code with root privileges via unknown vectors and corrupt memory.");
  script_tag(name:"affected", value:"Apple Safari version 6.x before 6.1.3 and 7.x before 7.0.3 on Mac OS X");
  script_tag(name:"solution", value:"Upgrade to Apple Safari version 6.1.3 or 7.0.3 or later.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://support.apple.com/kb/HT6181");
  script_xref(name:"URL", value:"http://secunia.com/advisories/57688");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("macosx_safari_detect.nasl");
  script_mandatory_keys("AppleSafari/MacOSX/Version");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!safVer = get_app_version(cpe:CPE)){
 exit(0);
}

if(version_in_range(version:safVer, test_version:"6.0", test_version2:"6.1.2") ||
   version_in_range(version:safVer, test_version:"7.0", test_version2:"7.0.2"))
{
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}
