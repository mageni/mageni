###############################################################################
# OpenVAS Vulnerability Test
#
# Apple Safari 'WebKit.dll' Stack Consumption Vulnerability
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.900870");
  script_version("2019-04-29T15:08:03+0000");
  script_tag(name:"last_modification", value:"2019-04-29 15:08:03 +0000 (Mon, 29 Apr 2019)");
  script_tag(name:"creation_date", value:"2009-09-24 10:05:51 +0200 (Thu, 24 Sep 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-3272");
  script_name("Apple Safari 'WebKit.dll' Stack Consumption Vulnerability");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/9606");
  script_xref(name:"URL", value:"http://en.securitylab.ru/nvd/385690.php");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Denial of Service");
  script_dependencies("secpod_apple_safari_detect_win_900003.nasl");
  script_mandatory_keys("AppleSafari/Version");
  script_tag(name:"impact", value:"Successful exploitation could allow attackers to cause stack consumption
  which may lead to the application crash.");
  script_tag(name:"affected", value:"Apple Safari version prior to 4.0");
  script_tag(name:"insight", value:"The flaw is due to error in 'WebKit.dll' in WebKit which can be caused via
  JavaScript code that calls eval on a long string composed of 'A/' sequences.");
  script_tag(name:"solution", value:"Upgrade to Safari version 4.0 or later.");
  script_tag(name:"summary", value:"This host has Apple Safari installed and is prone to Stack
  Consumption vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

safariVer = get_kb_item("AppleSafari/Version");
if(!safariVer)
  exit(0);

if(version_is_less(version:safariVer, test_version:"4.30.17.0")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
