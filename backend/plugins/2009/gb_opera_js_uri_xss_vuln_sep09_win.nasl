###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_opera_js_uri_xss_vuln_sep09_win.nasl 12629 2018-12-03 15:19:43Z cfischer $
#
# Opera 'javascript: URI' XSS Vulnerability - Sep09
#
# Authors:
# Sharath S <sharaths@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.800874");
  script_version("$Revision: 12629 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-03 16:19:43 +0100 (Mon, 03 Dec 2018) $");
  script_tag(name:"creation_date", value:"2009-09-07 19:45:38 +0200 (Mon, 07 Sep 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2009-3013");
  script_name("Opera 'javascript: URI' XSS Vulnerability - Sep09");
  script_xref(name:"URL", value:"http://websecurity.com.ua/3386/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_opera_detect_portable_win.nasl");
  script_mandatory_keys("Opera/Build/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to conduct Cross-Site Scripting
  attacks in the victim's system.");
  script_tag(name:"affected", value:"Opera version 9.52 and prior and 10.00 Beta 3 Build 1699 on Windows.");
  script_tag(name:"insight", value:"Error occurs when application fails to sanitise the 'javascript:' and 'data:'
  URIs in Location headers in HTTP responses, which can be exploited via vectors
  related to injecting a Location header.");
  script_tag(name:"solution", value:"Upgrade to Opera version 9.64 or later and 10.10 or later.");
  script_tag(name:"summary", value:"This host is installed with Opera Web Browser and is prone to
  Cross-Site Scripting vulnerability.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.opera.com/");
  exit(0);
}


include("version_func.inc");

operaVer = get_kb_item("Opera/Build/Win/Ver");
if(isnull(operaVer))
{
  exit(0);
}

#                        and 10.00 Beta 3 Build 1699 (10.0.1699.0)
if(version_is_less_equal(version:operaVer, test_version:"9.52.10108")||
   version_is_equal(version:operaVer, test_version:"10.0.1699.0")){
   security_message( port: 0, data: "The target host was found to be vulnerable" );
}
