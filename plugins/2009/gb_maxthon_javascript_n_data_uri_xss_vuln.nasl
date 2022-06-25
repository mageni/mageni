###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_maxthon_javascript_n_data_uri_xss_vuln.nasl 11554 2018-09-22 15:11:42Z cfischer $
#
# Maxthon 'javascript:' And 'data:' URI XSS Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.800897");
  script_version("$Revision: 11554 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-22 17:11:42 +0200 (Sat, 22 Sep 2018) $");
  script_tag(name:"creation_date", value:"2009-09-08 18:25:53 +0200 (Tue, 08 Sep 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2009-3018");
  script_name("Maxthon 'javascript:' And 'data:' URI XSS Vulnerability");
  script_xref(name:"URL", value:"http://websecurity.com.ua/3386/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/506163/100/0/threaded");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_maxthon_detect.nasl");
  script_mandatory_keys("Maxthon/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to conduct
Cross-Site Scripting attacks in the victim's system.");
  script_tag(name:"affected", value:"Maxthon version 3.0.0.145 on Windows.");
  script_tag(name:"insight", value:"Error occurs when application fails to sanitise the
'javascript:' and 'data:' URIs in Refresh headers or Location headers in HTTP
responses, which can be exploited via vectors related to injecting a Refresh
header or Location HTTP response header.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"This host is installed with Maxthon Browser and is prone to
  Cross-Site Scripting vulnerability.");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("version_func.inc");

maxthonVer = get_kb_item("Maxthon/Ver");

if(maxthonVer)
{
  if(version_is_equal(version:maxthonVer, test_version:"3.0.0.145")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
