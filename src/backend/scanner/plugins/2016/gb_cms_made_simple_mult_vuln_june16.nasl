###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cms_made_simple_mult_vuln_june16.nasl 12149 2018-10-29 10:48:30Z asteins $
#
# CMS Made Simple Multiple Vulnerabilities - June16
#
# Authors:
# Tushar Khelge <ktushar@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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

CPE = "cpe:/a:cmsmadesimple:cms_made_simple";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808061");
  script_version("$Revision: 12149 $");
  script_cve_id("CVE-2016-2784");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-29 11:48:30 +0100 (Mon, 29 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-06-07 16:34:53 +0530 (Tue, 07 Jun 2016)");
  script_name("CMS Made Simple Multiple Vulnerabilities - June16");

  script_tag(name:"summary", value:"The host is installed with CMS Made
  Simple and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request
  and check whether its able to read cookie value.");

  script_tag(name:"insight", value:"The multiple flaws exist due to,

  - Malicious content in a CMS Made Simple installation by poisoning the web server cache when Smarty Cache is
activated by modifying the Host HTTP Header in his request.

  - Lack of filtering of HTML entities in $_SERVER variable.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to obtain sensitive
information or conduct cross site scripting attacks.");

  script_tag(name:"affected", value:"CMS Made Simple version 2.x prior to 2.1.3 and version 1.x prior to 1.12.2");

  script_tag(name:"solution", value:"Upgrade to CMS Made Simple version 2.1.3 or 1.12.2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_probe");

  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/136897");
  script_xref(name:"URL", value:"http://www.cmsmadesimple.org/2016/04/Announcing-CMSMS-2-1-3-Black-Point");
  script_xref(name:"URL", value:"http://www.cmsmadesimple.org/2016/03/Announcing-CMSMS-1-12-2-kolonia");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("cms_made_simple_detect.nasl");
  script_mandatory_keys("cmsmadesimple/installed");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if(!cmsPort = get_app_port(cpe: CPE))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:cmsPort))
  exit(0);

if(dir == "/") dir = "";

url = dir+ "/index.php";

cmsReq =  'GET ' +url+ ' HTTP/1.1\r\n' +
          'Host: \' onload=\'javascrscript:ipt:alert(document.cookie)\r\n' +
          '\r\n';

cmsRes = http_keepalive_send_recv(port:cmsPort, data:cmsReq);

if(cmsRes =~ "HTTP/1\.. 200" && "alert(document.cookie)" >< cmsRes &&
      ">CMS Made Simple" >< cmsRes && "CMSMS Works" >< cmsRes)
{
  security_message(port:cmsPort);
  exit(0);
}

exit(0);
