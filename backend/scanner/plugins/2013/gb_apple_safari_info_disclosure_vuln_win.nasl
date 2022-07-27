###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apple_safari_info_disclosure_vuln_win.nasl 11883 2018-10-12 13:31:09Z cfischer $
#
# Apple Safari 'Webkit' Information Disclosure Vulnerability (Windows)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.804128");
  script_version("$Revision: 11883 $");
  script_cve_id("CVE-2013-5130");
  script_bugtraq_id(63289);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:31:09 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-11-06 11:11:36 +0530 (Wed, 06 Nov 2013)");
  script_name("Apple Safari 'Webkit' Information Disclosure Vulnerability (Windows)");


  script_tag(name:"impact", value:"Successful exploitation will allow attackers to obtain browsing information
by leveraging localstorage/files.");
  script_tag(name:"affected", value:"Apple Safari before 6.1 on Windows");
  script_tag(name:"insight", value:"The flaw exists due to unspecified vulnerability in the apple safari webkit");
  script_tag(name:"solution", value:"Upgrade to Apple Safari version 6.1 or later.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"summary", value:"This host is installed with Apple Safari and is prone to information
disclosure vulnerability.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/55448");
  script_xref(name:"URL", value:"http://lists.apple.com/archives/security-announce/2013/Oct/msg00003.html");
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("secpod_apple_safari_detect_win_900003.nasl");
  script_mandatory_keys("AppleSafari/Version");
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

safVer = get_app_version(cpe:CPE);
if(!safVer){
  exit(0);
}
if(version_is_less_equal(version:safVer, test_version:"5.34.57.2")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}

