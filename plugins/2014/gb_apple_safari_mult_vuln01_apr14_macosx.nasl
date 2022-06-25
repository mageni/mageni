###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apple_safari_mult_vuln01_apr14_macosx.nasl 14318 2019-03-19 11:44:05Z cfischer $
#
# Apple Safari Multiple Memory Corruption Vulnerabilities-01 Apr14 (Mac OS X)
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
  script_oid("1.3.6.1.4.1.25623.1.0.804533");
  script_version("$Revision: 14318 $");
  script_cve_id("CVE-2014-1300", "CVE-2014-1303");
  script_bugtraq_id(66583, 66242);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 12:44:05 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2014-04-07 12:52:16 +0530 (Mon, 07 Apr 2014)");
  script_name("Apple Safari Multiple Memory Corruption Vulnerabilities-01 Apr14 (Mac OS X)");

  script_tag(name:"summary", value:"This host is installed with Apple Safari and is prone to multiple
  vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Flaws are due to muliple unspecified errors in the WebKit");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to bypass a sandbox protection
  mechanism, execute arbitrary code with root privileges via unknown vectors and corrupt memory.");
  script_tag(name:"affected", value:"Apple Safari version 7.0.2 on Mac OS X");
  script_tag(name:"solution", value:"Upgrade to Apple Safari version 7.0.3 or later.");
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

if(version_is_equal(version:safVer, test_version:"7.0.2"))
{
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}
