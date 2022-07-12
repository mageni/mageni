###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_opera_xss_vuln_lin.nasl 12629 2018-12-03 15:19:43Z cfischer $
#
# Opera Web Browser 'Refresh' Header XSS Vulnerabilities (Linux)
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800652");
  script_version("$Revision: 12629 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-03 16:19:43 +0100 (Mon, 03 Dec 2018) $");
  script_tag(name:"creation_date", value:"2009-07-09 10:58:23 +0200 (Thu, 09 Jul 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2009-2351");
  script_bugtraq_id(35571);
  script_name("Opera Web Browser 'Refresh' Header XSS Vulnerabilities (Linux)");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/504718/100/0/threaded");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_opera_detection_linux_900037.nasl");
  script_mandatory_keys("Opera/Linux/Version");
  script_tag(name:"impact", value:"Successful remote attack could execute arbitrary script code in the context
  of the user running the application and to steal cookie-based authentication
  credentials and other sensitive data that may aid in further attacks.");
  script_tag(name:"affected", value:"Opera version 9.52 and prior on Linux.");
  script_tag(name:"insight", value:"Flaw is due to error in Refresh headers in HTTP responses. It does not block
  javascript: URIs, while injecting a Refresh header or specifying the content
  of a Refresh header");
  script_tag(name:"solution", value:"Upgrade to Opera version 9.64 or later.");
  script_tag(name:"summary", value:"The host is installed with Opera Web Browser and is prone to
  Cross-Site Scripting Vulnerability.");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.opera.com/download/");
  exit(0);
}


include("version_func.inc");

operaVer = get_kb_item("Opera/Linux/Version");
if(!operaVer){
  exit(0);
}

if(version_is_less_equal(version:operaVer, test_version:"9.52")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
