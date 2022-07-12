###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apple_safari_libxml_dos_vuln.nasl 12653 2018-12-04 15:31:25Z cfischer $
#
# Apple Safari libxml Denial of Service Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.801638");
  script_version("$Revision: 12653 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-04 16:31:25 +0100 (Tue, 04 Dec 2018) $");
  script_tag(name:"creation_date", value:"2010-11-23 14:41:37 +0100 (Tue, 23 Nov 2010)");
  script_cve_id("CVE-2010-4008");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_name("Apple Safari libxml Denial of Service Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/42175/");
  script_xref(name:"URL", value:"http://blog.bkis.com/en/libxml2-vulnerability-in-google-chrome-and-apple-safari/");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_apple_safari_detect_win_900003.nasl");
  script_mandatory_keys("AppleSafari/Version");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to cause a denial
of service.");
  script_tag(name:"affected", value:"Apple Safari version 5.0.2 and prior.");
  script_tag(name:"insight", value:"The flaw is due to an error when traversing the XPath axis of
certain XML files. This can be exploited to cause a crash when an application
using the library processes a specially crafted XML file.");
  script_tag(name:"solution", value:"Upgrade to Apple Safari 5.0.4 or later.");
  script_tag(name:"summary", value:"The host is installed with Apple Safari web browser and is prone
  to denial of service vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.apple.com/support/downloads");
  exit(0);
}


include("version_func.inc");

safVer = get_kb_item("AppleSafari/Version");
if(!safVer){
  exit(0);
}

if(version_is_less_equal(version:safVer, test_version:"5.33.18.5")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
