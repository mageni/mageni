###############################################################################
# OpenVAS Vulnerability Test
# $Id: notftp_detect.nasl 13865 2019-02-26 07:43:10Z ckuersteiner $
#
# NotFTP Detection
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.100160");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 13865 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-26 08:43:10 +0100 (Tue, 26 Feb 2019) $");
  script_tag(name:"creation_date", value:"2009-04-24 20:04:08 +0200 (Fri, 24 Apr 2009)");
  script_tag(name:"cvss_base", value:"0.0");

  script_name("NotFTP Detection");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"This host is running NotFTP, a Web-based HTTP-FTP gateway written in PHP.");

  script_xref(name:"URL", value:"http://sourceforge.net/projects/notftp/");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

port = get_http_port(default:80);

if(!can_host_php(port:port))exit(0);

foreach dir( make_list_unique( "/ftp", "/webftp", "/notftp", cgi_dirs( port:port ) ) ) {
 install = dir;
 if( dir == "/" ) dir = "";

 url = dir + "/index.php";
 buf = http_get_cache( item:url, port:port );
 if( buf == NULL ) continue;

 if ((egrep(pattern: 'NotFTP</a> is <a [^>]+>OSI Certified', string: buf, icase: TRUE) &&
     egrep(pattern: 'form action="ftp.php"', string: buf)) ||
     "<title>NotFTP" >< buf && '<form action="ftp.php"' >< buf ) {
   vers = "unknown";

   version = eregmatch(string: buf, pattern: "NotFTP v([0-9.]+)",icase:TRUE);
   if ( !isnull(version[1]) ) {
      vers = version[1];
   } else {
     foreach file (make_list("/README", "/readme")) {
       url = dir + file;
       buf = http_get_cache(port: port, item: url);
       if( buf == NULL )continue;

       version = eregmatch(string: buf, pattern: "NotFTP v([0-9.]+)",icase:TRUE);

       if ( !isnull(version[1]) ) {
	 vers = version[1];
         concUrl = url;
	 break;
       }
     }
   }

   set_kb_item(name:"notftp/detected", value: TRUE);

   cpe = build_cpe(value:vers, exp:"^([0-9.]+)", base:"cpe:/a:wonko:notftp:");
   if (!cpe)
     cpe = 'cpe:/a:wonko:notftp';

   register_product(cpe: cpe, location: install, port: port, service: "www");

   log_message(data: build_detection_report(app: "NotFTP", version: vers, install: install, cpe: cpe,
                                            concluded: version[0], concludedUrl: concUrl),
               port: port);
   exit(0);
 }
}

exit(0);
