###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_lotus_notes_web_app_xss_vuln_macosx.nasl 11865 2018-10-12 10:03:43Z cfischer $
#
# IBM Lotus Notes Web Application XSS Vulnerability (Mac OS X)
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803218");
  script_version("$Revision: 11865 $");
  script_cve_id("CVE-2012-4846");
  script_bugtraq_id(56944);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:03:43 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-01-23 15:38:23 +0530 (Wed, 23 Jan 2013)");
  script_name("IBM Lotus Notes Web Application XSS Vulnerability (Mac OS X)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/51593");
  script_xref(name:"URL", value:"http://securitytracker.com/id?1027887");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/79535");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21619604");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_ibm_lotus_notes_detect_macosx.nasl");
  script_mandatory_keys("IBM/LotusNotes/MacOSX/Ver");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary HTML and
  script code in a user's browser session in context of an affected site.");

  script_tag(name:"affected", value:"IBM Lotus Notes Version 8.x before 8.5.3 FP3 on Mac OS X");

  script_tag(name:"insight", value:"An error exists within the Web applications which allows an attacker to read
  or set the cookie value by injecting script.");

  script_tag(name:"solution", value:"Upgrade to IBM Lotus Notes 8.5.3 FP3");

  script_tag(name:"summary", value:"This host is installed with IBM Lotus Notes and is prone to cross
  site scripting vulnerability.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

lotusVer = get_kb_item("IBM/LotusNotes/MacOSX/Ver");
if(!lotusVer){
 exit(0);
}

if(version_in_range(version:lotusVer, test_version:"8.5.0",
                                      test_version2:"8.5.3.2")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
