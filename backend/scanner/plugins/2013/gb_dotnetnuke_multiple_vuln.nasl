###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dotnetnuke_multiple_vuln.nasl 11865 2018-10-12 10:03:43Z cfischer $
#
# DotNetNuke Redirection Weakness and Cross Site Scripting Vulnerabilities
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
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

CPE = "cpe:/a:dotnetnuke:dotnetnuke";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803874");
  script_version("$Revision: 11865 $");
  script_cve_id("CVE-2013-3943", "CVE-2013-4649", "CVE-2013-7335");
  script_bugtraq_id(61809, 61770);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:03:43 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-08-21 15:43:57 +0530 (Wed, 21 Aug 2013)");
  script_name("DotNetNuke Redirection Weakness and Cross Site Scripting Vulnerabilities");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_dotnetnuke_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("dotnetnuke/installed");

  script_tag(name:"summary", value:"This host is installed with DotNetNuke and is prone to redirection weakness
  and cross site scripting vulnerabilities.");
  script_tag(name:"vuldetect", value:"Send a Crafted HTTP GET request and check whether it is able to read the
  cookie or not.");
  script_tag(name:"solution", value:"Upgrade to version 6.2.9 or 7.1.1 or later.");
  script_tag(name:"insight", value:"Multiple flaws are due to,

  - Input related to the 'Display Name' field in 'Manage Profile' is not properly
  sanitised before being used.

  - Input passed via the '__dnnVariable' GET parameter to Default.aspx is not
  properly sanitised before being returned to the user.

  - Certain unspecified input is not properly verified before being used to
  redirect users.");
  script_tag(name:"affected", value:"DotNetNuke versions 6.x before 6.2.9 and 7.x before 7.1.1");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to insertion attacks and conduct
  spoofing and cross-site scripting attacks.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/53493");
  script_xref(name:"URL", value:"http://cxsecurity.com/issue/WLB-2013080113");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/122792");
  script_xref(name:"URL", value:"http://www.securelist.com/en/advisories/53493");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");

  script_xref(name:"URL", value:"http://dnnsoftware.com");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 );

if( dir == "/" ) dir = "";

url = dir + "/?__dnnVariable={%27__dnn_pageload%27:%27alert%28document.cookie%29%27}";

## Extra check is not possible in this case.
if( http_vuln_check( port:port, url:url, check_header:TRUE,
                     pattern:"alert\(document.cookie\)" ) ) {
  report = report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );