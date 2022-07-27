###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apple_safari_address_bar_spoofin_vuln_win.nasl 11857 2018-10-12 08:25:16Z cfischer $
#
# Apple Safari 'setInterval()' Address Bar Spoofing Vulnerability (Windows)
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802818");
  script_version("$Revision: 11857 $");
  script_cve_id("CVE-2011-3844");
  script_bugtraq_id(52323);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 10:25:16 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-03-13 18:17:52 +0530 (Tue, 13 Mar 2012)");
  script_name("Apple Safari 'setInterval()' Address Bar Spoofing Vulnerability (Windows)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/44976");
  script_xref(name:"URL", value:"http://securitytracker.com/id/1026775");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/73712");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_apple_safari_detect_win_900003.nasl");
  script_mandatory_keys("AppleSafari/Version");
  script_tag(name:"impact", value:"Successful exploitation will let attackers to conduct spoofing attacks via a
  crafted HTML document.");
  script_tag(name:"affected", value:"Apple Safari version 5.0.5 on Windows");
  script_tag(name:"insight", value:"The flaw is due to an improper implementation of the setInterval
  function, which allows remote attackers to spoof the address bar via a
  crafted web page.");
  script_tag(name:"solution", value:"Upgrade to Apple Safari version 5.1.2 or later.");
  script_tag(name:"summary", value:"This host is installed with Apple Safari web browser and is prone
  to address bar spoofing vulnerability.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.apple.com/support/downloads/");
  exit(0);
}


include("version_func.inc");

safVer = get_kb_item("AppleSafari/Version");
if(!safVer){
  exit(0);
}

if(version_is_equal(version:safVer, test_version:"5.33.21.1")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
