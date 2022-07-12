###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_aiocp_remote_file_inclusion.nasl 14323 2019-03-19 13:19:09Z jschulte $
#
# AIOCP 'cp_html2xhtmlbasic.php' Remote File Inclusion Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.801201");
  script_version("$Revision: 14323 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 14:19:09 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-04-07 16:20:50 +0200 (Wed, 07 Apr 2010)");
  script_cve_id("CVE-2009-4747");
  script_bugtraq_id(36609);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("AIOCP 'cp_html2xhtmlbasic.php' Remote File Inclusion Vulnerability");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/53679");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/507030/100/0/threaded");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary
  code in the context of an application.");
  script_tag(name:"affected", value:"All In One Control Panel (AIOCP) 1.4.001 and prior");
  script_tag(name:"insight", value:"The flaw is caused by improper validation of user-supplied
  input via the 'page' parameter in cp_html2xhtmlbasic.php that allows the
  attackers to execute arbitrary code on the web server.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"This host is running All In One Control Panel (AIOCP) and is
  prone to remote file inclusion vulnerability.");

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

foreach dir (make_list_unique("/", "/AIOCP", "/aiocp", cgi_dirs(port:port)))
{

  if(dir == "/") dir = "";

  req = http_get(item:string(dir,"/public/code/cp_dpage.php"),  port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

  if('Powered by Tecnick.com AIOCP' >< res)
  {
    req = http_get(item:string(dir,"/public/code/cp_html2xhtmlbasic.php?page=",
    "http://",get_host_ip(),dir,"/public/code/cp_contact_us.php"), port:port);
    res = http_keepalive_send_recv(port:port, data:req);

    if((">Contact us<" >< res) && (">name<" >< res) && (">email<" >< res))
    {
      security_message(port:port);
      exit(0);
    }
  }
}

exit(99);