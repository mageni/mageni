###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_firefox_unspecified_vuln_mar10_win.nasl 12653 2018-12-04 15:31:25Z cfischer $
#
# Mozilla Firefox Unspecified Vulnerability Mar-10 (Windows)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902147");
  script_version("$Revision: 12653 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-04 16:31:25 +0100 (Tue, 04 Dec 2018) $");
  script_tag(name:"creation_date", value:"2010-03-30 16:15:33 +0200 (Tue, 30 Mar 2010)");
  script_cve_id("CVE-2010-1122");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Mozilla Firefox Unspecified Vulnerability Mar-10 (Windows)");


  script_copyright("Copyright (c) 2010 SecPod");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_firefox_detect_portable_win.nasl");
  script_mandatory_keys("Firefox/Win/Ver");
  script_tag(name:"impact", value:"Impact is currently unknown.");
  script_tag(name:"affected", value:"Mozilla Firefox version 3.5.x through 3.5.8.");
  script_tag(name:"insight", value:"Vulnerability details are not available.");
  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 3.6.3 or later");
  script_tag(name:"summary", value:"The host is installed with mozilla firefox and is prone to
  unspecified vulnerability.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://en.securitylab.ru/nvd/392231.php");
  script_xref(name:"URL", value:"http://www.security-database.com/cvss.php?alert=CVE-2010-1122");
  script_xref(name:"URL", value:"http://www.mozilla.com/en-US/firefox/upgrade.html");
  exit(0);
}


include("version_func.inc");

fpVer = get_kb_item("Firefox/Win/Ver");
if(!fpVer){
  exit(0);
}

if(version_in_range(version:fpVer, test_version:"3.5.0", test_version2:"3.5.8")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
