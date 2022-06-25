##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_calendarix_xss_n_sql_inj_vuln.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# Calendarix Cross Site Scripting and SQL Injection Vulnerabilities
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.801793");
  script_version("$Revision: 11997 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-06-02 11:54:09 +0200 (Thu, 02 Jun 2011)");
  script_bugtraq_id(47790);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Calendarix Cross Site Scripting and SQL Injection Vulnerabilities");
  script_xref(name:"URL", value:"http://secunia.com/advisories/33876/");
  script_xref(name:"URL", value:"http://securityreason.com/wlb_show/WLB-2011050051");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/101295/calendarix-sqlxss.txt");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"insight", value:"The flaws are due to:

  - Improper validation of user supplied input to '/cal_login.php' script.

  - Failure in the '/cal_date.php' script to properly sanitize user-supplied
  input in 'leftfooter' and 'frmname' variables.

  - Improper validation of user supplied input to '/cal_catview.php' via 'gocat'
  variable.

  - Failure in the 'cal_login.php' script to properly sanitize user-supplied
  input via 'login' field when 'password' field is set empty.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"This host is running Calendarix and is prone to cross site scripting
  and SQL injection vulnerabilities.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute
  arbitrary HTML and script code and manipulate SQL queries by injecting arbitrary
  SQL code in a user's browser session in the context of an affected site.");
  script_tag(name:"affected", value:"Calendarix version 0.8.20080808");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

calPort = get_http_port(default:80);

if(!can_host_php(port:calPort)){
  exit(0);
}

foreach path (make_list_unique("/calendarix", "/", cgi_dirs(port:calPort)))
{

  if(path == "/") path = "";

  rcvRes = http_get_cache(item: path + "/calendar.php", port:calPort);

  if('About Calendarix' >< rcvRes || 'Calendarix version' >< rcvRes)
  {
    sndReq = http_get(item:string(path, "/cal_login.php/'><script>alert"
                      + "('OpenVAS-XSS-Test');</script>"), port:calPort);
    rcvRes = http_keepalive_send_recv(port:calPort, data:sndReq);

    if(rcvRes =~ "HTTP/1\.. 200" && "><script>alert('OpenVAS-XSS-Test');</script>" >< rcvRes)
    {
      security_message(port:calPort);
      exit(0);
    }
  }
}

exit(99);
