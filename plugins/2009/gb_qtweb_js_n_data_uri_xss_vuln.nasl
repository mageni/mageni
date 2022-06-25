###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_qtweb_js_n_data_uri_xss_vuln.nasl 14325 2019-03-19 13:35:02Z asteins $
#
# QtWeb 'javascript:' And 'data:' URI XSS Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.800899");
  script_version("$Revision: 14325 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 14:35:02 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2009-09-08 18:25:53 +0200 (Tue, 08 Sep 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2009-3018");
  script_name("QtWeb 'javascript:' And 'data:' URI XSS Vulnerability");
  script_xref(name:"URL", value:"http://websecurity.com.ua/3386/");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/52993");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_qtweb_detect.nasl");
  script_mandatory_keys("QtWeb/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to conduct Cross-Site Scripting
  attacks in the victim's system.");
  script_tag(name:"affected", value:"QtWeb version 3.0.0.145 on Windows.");
  script_tag(name:"insight", value:"Error occurs when application fails to sanitise the 'javascript:' and 'data:'
  URIs in Refresh headers or Location headers in HTTP responses, which can be
  exploited via vectors related to injecting a Refresh header or Location HTTP
  response header.");
  script_tag(name:"solution", value:"Upgrade to QtWeb version 3.2 or later");
  script_tag(name:"summary", value:"This host is installed with QtWeb Browser and is prone to
  Cross-Site Scripting vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.qtweb.net/");
  exit(0);
}


include("version_func.inc");

qtwebVer = get_kb_item("QtWeb/Ver");

if(qtwebVer)
{
  if(version_is_equal(version:qtwebVer, test_version:"3.0.0.3")||
     version_is_equal(version:qtwebVer, test_version:"3.0.0.1")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
