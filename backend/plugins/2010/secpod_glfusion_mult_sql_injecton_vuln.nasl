###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_glfusion_mult_sql_injecton_vuln.nasl 14323 2019-03-19 13:19:09Z jschulte $
#
# glFusion Multiple SQL Injection Vulnerabilities
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.901111");
  script_version("$Revision: 14323 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 14:19:09 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-04-29 10:04:32 +0200 (Thu, 29 Apr 2010)");
  script_cve_id("CVE-2009-4796");
  script_bugtraq_id(34281);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("glFusion Multiple SQL Injection Vulnerabilities");
  script_xref(name:"URL", value:"http://secunia.com/advisories/34519");
  script_xref(name:"URL", value:"http://retrogod.altervista.org/9sg_glfusion_sql.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/502260/100/0/threaded");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will let the attacker cause SQL injection attack and
  gain sensitive information.");
  script_tag(name:"affected", value:"glFusion version 1.1.2 and prior.");
  script_tag(name:"insight", value:"The flaws are due to improper validation of user supplied input via
  the 'order' and 'direction' parameters to 'search.php' that allows attacker
  to manipulate SQL queries by injecting arbitrary SQL code.");
  script_tag(name:"solution", value:"Upgrade to the latest version of glFusion 1.1.8 or later.");
  script_tag(name:"summary", value:"This host is running glFusion and is prone to multiple SQL
  injection vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");
  script_xref(name:"URL", value:"http://www.glfusion.org/filemgmt/index.php");
  exit(0);
}


include("http_func.inc");
include("version_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!can_host_php(port:port)){
  exit(0);
}

foreach dir (make_list_unique("/", "/glFusion", "/glfusion/public_html", cgi_dirs(port:port)))
{

  if(dir == "/") dir = "";

  res = http_get_cache(item: dir + "/index.php",  port:port);

  if('>glFusion' >< res)
  {
    ver = eregmatch(pattern:"glFusion v([0-9.]+)", string:res);
    if(ver[1]!= NULL)
    {
      if(version_is_less_equal(version:ver[1], test_version:"1.1.2"))
      {
        security_message(port:port);
        exit(0);
      }
    }
  }
}

exit(99);