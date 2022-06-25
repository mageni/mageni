###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_feng_office_ref_xxx_xss_vuln.nasl 11865 2018-10-12 10:03:43Z cfischer $
#
# Feng Office ref_XXX XSS Vulnerability
#
# Authors:
# Shashi Kiran N <nskiran@secpod.com>
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

CPE = "cpe:/a:fengoffice:feng_office";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803959");
  script_version("$Revision: 11865 $");
  script_cve_id("CVE-2013-5744");
  script_bugtraq_id(62591);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:03:43 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-11-05 18:42:22 +0530 (Tue, 05 Nov 2013)");
  script_name("Feng Office ref_XXX XSS Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_feng_office_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("FengOffice/installed");

  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2013/Oct/33");
  script_xref(name:"URL", value:"https://www.htbridge.com/advisory/HTB23174");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/123556");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to steal the victim's
  cookie-based authentication credentials.");
  script_tag(name:"affected", value:"Feng Office 2.3.2-rc and earlier");
  script_tag(name:"insight", value:"An error exists in the application which fails to properly sanitize user-supplied
  input to 'ref_XXX' parameter before using it");
  script_tag(name:"solution", value:"Upgrade to Feng Office 2.5-beta or later.");
  script_tag(name:"vuldetect", value:"Send a crafted exploit string via HTTP GET request and check whether it is able to
  read the string or not.");
  script_tag(name:"summary", value:"This host is installed with Feng Office and is prone to cross-site scripting
  Vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  script_xref(name:"URL", value:"http://www.fengoffice.com");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 );

if( dir == "/" ) dir = "";

url = dir + '/index.php?c=access&a=login&ref_abc="><script>alert(document.cookie);</script>';

if( http_vuln_check( port:port, url:url, check_header:TRUE, pattern:"<script>alert\(document.cookie\);</script>" ) ) {
  report = report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );