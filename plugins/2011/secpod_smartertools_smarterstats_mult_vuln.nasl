###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_smartertools_smarterstats_mult_vuln.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# SmarterTools SmarterStats Multiple Vulnerabilities
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902773");
  script_version("$Revision: 11997 $");
  script_cve_id("CVE-2011-4752", "CVE-2011-4751", "CVE-2011-4750");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"creation_date", value:"2011-12-21 16:43:05 +0530 (Wed, 21 Dec 2011)");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_name("SmarterTools SmarterStats Multiple Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 SecPod");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 9999);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.smartertools.com/smarterstats/web-analytics-seo-software.aspx");
  script_xref(name:"URL", value:"http://xss.cx/examples/exploits/stored-reflected-xss-cwe79-smarterstats624100.html");

  script_tag(name:"impact", value:"Successful exploitation will let the attackers execute arbitrary
  HTML and script code in a user's browser session in context of an affected site.");
  script_tag(name:"affected", value:"SmarterTools SmarterStats version 6.2.4100");
  script_tag(name:"insight", value:"The flaws are due to an,

  - Input passed via multiple parameters to multiple scripts are not properly
  sanitised before being returned to the user.

  - Error in 'frmGettingStarted.aspx' generates response with GET request,
  which allows remote attackers obtain sensitive information by reading
  web-server access logs or and web-server referer logs.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"This host is SmarterTools SmarterStats and is prone to multiple
  vulnerabilities.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("version_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:9999);
if( ! can_host_asp( port:port ) ) exit( 0 );

rcvRes = http_get_cache(item: "/login.aspx", port:port);

if("Login to SmarterStats" >< rcvRes || ">SmarterStats" >< rcvRes) {
  ver = eregmatch(pattern:">SmarterStats.?([a-zA-Z]+?.?([0-9.]+))", string:rcvRes);
  if(ver[2] =~ "^[0-9]"){
    ver = ver[2];
  } else{
    ver = ver[1];
  }
}

if(ver) {
  if(version_in_range(version:ver, test_version:"6.2", test_version2:"6.2.4100")){
    security_message(port);
  }
}
