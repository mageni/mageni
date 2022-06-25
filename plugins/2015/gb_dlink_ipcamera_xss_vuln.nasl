###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dlink_ipcamera_xss_vuln.nasl 11872 2018-10-12 11:22:41Z cfischer $
#
# D-link IP Camera DCS-2103 Cross-site Scripting Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.805034");
  script_version("$Revision: 11872 $");
  script_cve_id("CVE-2014-9517");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:22:41 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-01-08 11:21:29 +0530 (Thu, 08 Jan 2015)");
  script_name("D-link IP Camera DCS-2103 Cross-site Scripting Vulnerability");

  script_tag(name:"summary", value:"This host has D-link IP Camera and is
  prone to cross-site scripting vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted HTTP GET request and check
  whether it is able read the cookie");

  script_tag(name:"insight", value:"The flaw is due to an input passed via
  the vb.htm script to the 'QUERY_STRING ' parameter is not properly sanitized.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to
  execute arbitrary HTML and script code in a user's browser session in the context
  of an affected site.");

  script_tag(name:"affected", value:"D-link IP camera DCS-2103 with firmware before 1.20");

  script_tag(name:"solution", value:"Upgrade to D-link IP camera DCS-2103 with
  firmware 1.20 or later.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/129609");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("DCS-2103/banner");

  script_xref(name:"URL", value:"http://www.dlink.com");
  exit(0);
}


include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

DlinkPort = get_http_port(default:80);

DlinkBanner = get_http_banner(port: DlinkPort);
if('WWW-Authenticate: Basic realm="DCS-2103"' >!< DlinkBanner){
  exit(0);
}

url ="/vb.htm?<script>alert(document.cookie)</script>";

## Extra Check is not possible
if(http_vuln_check(port:DlinkPort, url:url, check_header:TRUE,
   pattern:"<script>alert\(document.cookie\)</script>"))
{
  report = report_vuln_url( port:DlinkPort, url:url );
  security_message(port:DlinkPort, data:report);
  exit(0);
}

