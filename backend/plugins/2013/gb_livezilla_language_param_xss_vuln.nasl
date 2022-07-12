###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_livezilla_language_param_xss_vuln.nasl 11865 2018-10-12 10:03:43Z cfischer $
#
# LiveZilla 'g_language' Parameter Cross Site Scripting Vulnerability
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

CPE = "cpe:/a:livezilla:livezilla";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803785");
  script_version("$Revision: 11865 $");
  script_cve_id("CVE-2013-7002", "CVE-2013-6224");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:03:43 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-12-17 13:21:53 +0530 (Tue, 17 Dec 2013)");
  script_name("LiveZilla 'g_language' Parameter Cross Site Scripting Vulnerability");

  script_tag(name:"summary", value:"The host is installed with LiveZilla and is prone to cross site scripting
  vulnerability.");
  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request and check whether it is able
  read the cookie or not.");
  script_tag(name:"solution", value:"Upgrade to LiveZilla 5.1.1.0 or later.");
  script_tag(name:"insight", value:"- The flaw is due to input passed via the 'g_language' GET parameter to
   '/mobile/php/translation/index.php' is not properly sanitised before
   being returned to the user.

  - Input passed via the username and message body to chat.php when starting
   a new chat session is not properly sanitised before being used.");
  script_tag(name:"affected", value:"LiveZilla version 5.1.0.0");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary HTML
  and script code in a users browser session in the context of an affected site
  and launch other attacks.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/54505");
  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2013/Dec/31");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/124344");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/530209");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_livezilla_detect.nasl");
  script_mandatory_keys("LiveZilla/installed");
  script_require_ports("Services/www", 80);

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_app");

  script_xref(name:"URL", value:"http://livezilla.net");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!lzPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!dir = get_app_location(cpe:CPE, port:lzPort)){
  exit(0);
}

if( dir == "/" ) dir = "";

url = dir + "/mobile/php/translation/index.php?g_language=f%27%3E%3C" +
            "img%20src=a%20onerror=alert%28document.cookie%29%3Eh";

if(http_vuln_check(port:lzPort, url: url, check_header: TRUE,
   pattern: "onerror=alert\(document.cookie\)",
   extra_check: make_list("LiveZilla Mobile", "Translation management")))
{
  security_message(port:lzPort);
  exit(0);
}

exit(99);