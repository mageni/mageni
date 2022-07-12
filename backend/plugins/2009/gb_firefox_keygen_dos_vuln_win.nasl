###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_firefox_keygen_dos_vuln_win.nasl 12629 2018-12-03 15:19:43Z cfischer $
#
# Mozilla Firefox 'keygen' HTML Tag DOS Vulnerability (Windows)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.800624");
  script_version("$Revision: 12629 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-03 16:19:43 +0100 (Mon, 03 Dec 2018) $");
  script_tag(name:"creation_date", value:"2009-06-04 07:18:37 +0200 (Thu, 04 Jun 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-1828", "CVE-2009-1827");
  script_bugtraq_id(35132);
  script_name("Mozilla Firefox 'keygen' HTML Tag DOS Vulnerability (Windows)");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/8794");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/50721");
  script_xref(name:"URL", value:"http://blog.zoller.lu/2009/04/advisory-firefox-denial-of-service.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_firefox_detect_portable_win.nasl");
  script_mandatory_keys("Firefox/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation will let attackers to cause the browser to stop
  responding, infinite loop, application hang, and memory consumption, and
  can cause denying service to legitimate users.");
  script_tag(name:"affected", value:"Firefox version 3.0.4 and 3.0.10 on Windows");
  script_tag(name:"insight", value:"- Error exists via KEYGEN element in conjunction with a META element
    specifying automatic page refresh or a JavaScript onLoad event handler
    for a BODY element.

  - Error caused while passing a large value in the r (aka Radius) attribute
    of a circle element, related to an 'unclamped loop.'.");
  script_tag(name:"solution", value:"Upgrade to Firefox version 3.6.3 or later.");
  script_tag(name:"summary", value:"The host is installed with Mozilla Firefox browser and is prone
  to Denial of Service vulnerability.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.mozilla.com/en-US/");
  exit(0);
}


include("version_func.inc");

ffVer = get_kb_item("Firefox/Win/Ver");
if(!ffVer){
  exit(0);
}

if(version_is_equal(version:ffVer, test_version:"3.0.10")||
   version_is_equal(version:ffVer, test_version:"3.0.4")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
