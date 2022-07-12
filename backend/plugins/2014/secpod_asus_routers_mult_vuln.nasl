##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_asus_routers_mult_vuln.nasl 14185 2019-03-14 13:43:25Z cfischer $
#
# ASUS Router Multiple Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2014 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.903432");
  script_version("$Revision: 14185 $");
  script_cve_id("CVE-2015-1437");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2019-03-14 14:43:25 +0100 (Thu, 14 Mar 2019) $");
  script_tag(name:"creation_date", value:"2014-02-26 16:37:32 +0530 (Wed, 26 Feb 2014)");
  script_name("ASUS Router Multiple Vulnerabilities");

  script_tag(name:"summary", value:"The host is running ASUS Router and is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted exploit string via HTTP GET request and check whether it
  is possible to read cookie or not.");

  script_tag(name:"insight", value:"- The error page is accessible without authentication. This allows the
  attacker to bypass same-origin policy restrictions enforced by XMLHttpRequest.

  - The router error page 'error_page.htm' includes the current administrative
  password in clear text.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to insert arbitrary HTML
  and script code, which will be executed in a user's browser session in the
  context of an affected site and also can conduct phishing attacks.");

  script_tag(name:"affected", value:"- ASUS RT-N16

  - ASUS RT-N10U, firmware 3.0.0.4.374_168

  - ASUS RT-N56U, firmware 3.0.0.4.374_979

  - ASUS DSL-N55U, firmware 3.0.0.4.374_1397

  - ASUS RT-AC66U, firmware 3.0.0.4.374_2050

  - ASUS RT-N15U, firmware 3.0.0.4.374_16

  - ASUS RT-N53, firmware 3.0.0.4.374_311");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the
  disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to
  upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"https://sintonen.fi/advisories/asus-router-auth-bypass.txt");
  script_xref(name:"URL", value:"http://www.asus.com/Networking/RTN56U");
  script_xref(name:"URL", value:"http://exploitsdownload.com/exploit/na/asus-router-authentication-bypass-cross-site-scripting");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2014 SecPod");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

asport = get_http_port(default:80);
banner = get_http_banner(port: asport);

if(banner =~ 'WWW-Authenticate: Basic realm=".*(RT-|DSL-).*"')
{
  url = "/error_page.htm?flag=%27%2balert(document.cookie)%2b%27";

  if(http_vuln_check(port:asport, url:url, pattern:"alert\(document.cookie\)", check_header:TRUE,
     extra_check:make_list("reboot_time")))
  {
    security_message(port:asport);
    exit(0);
  }
}
