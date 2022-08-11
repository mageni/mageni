###############################################################################
# OpenVAS Vulnerability Test
# $Id: mambo_detect.nasl 12818 2018-12-18 09:55:03Z ckuersteiner $
#
# mambo Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.100036");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 12818 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-18 10:55:03 +0100 (Tue, 18 Dec 2018) $");
  script_tag(name:"creation_date", value:"2009-03-13 06:42:27 +0100 (Fri, 13 Mar 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("mambo Detection");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"This host is running mambo a widely installed Open Source cms solution.");

  script_xref(name:"URL", value:"http://www.mamboserver.com");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

SCRIPT_DESC = "mambo Detection";

port = get_http_port(default:80);
if(!can_host_php(port:port)) exit(0);

foreach dir( make_list_unique( "/mambo", "/cms", cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" ) dir = "";
  url = dir + "/index.php";
  buf = http_get_cache( item:url, port:port );
  if( buf == NULL ) continue;

  if( egrep(pattern: "^Set-Cookie: mosvisitor=1", string: buf)   ||
      egrep(pattern: '.*meta name="description" content="This site uses Mambo.*', string: buf) ||
      egrep(pattern: '.*meta name="Generator" content="Mambo.*', string: buf) ||
      egrep(pattern: '.*http://mambo-foundation.org<[^>]+>Mambo.*', string: buf) ) {
    installed = TRUE;
  } else {
    url = string(dir, "/htaccess.txt");
    req = http_get(item:url, port:port);
    buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
    if( buf == NULL )continue;

    if( egrep(pattern: ".*# @package Mambo.*", string: buf) ) {
      installed = TRUE;
    } else {
      url = string(dir, "/README.php");
      req = http_get(item:url, port:port);
      buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
      if( buf == NULL )continue;

      if( egrep(pattern: "^Mambo is Open Source software.*", string: buf ) ) {
        installed = TRUE;
      } else {
        url = string(dir, "/includes/js/mambojavascript.js");
        req = http_get(item:url, port:port);
        buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
        if( buf == NULL )continue;

        if( egrep(pattern: ".*@package Mambo.*", string: buf) ) {
          installed = TRUE;
        }
      }
    }
  }

  if( installed ) {
    vers = "unknown";

    url = dir + "/administrator/components/com_admin/version.xml";
    req = http_get(item:url, port:port);
    buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
    version = eregmatch(string: buf, pattern: "<version>(.*)</version>");

    if ( !isnull(version[1]) ) {
      vers=version[1];
      concUrl = url;
    } else {
      url = string(dir, "/mambots/content/moscode.xml");
      req = http_get(item:url, port:port);
      buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
      version = eregmatch(string: buf, pattern: ".*<version>(.*)</version>.*");

      if ( !isnull(version[1]) ) {
        vers=version[1];
        concUrl = url;
      } else {
        url = string(dir, "/help/mambo.whatsnew.html");
        req = http_get(item:url, port:port);
        buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
        version = eregmatch(string: buf, pattern: ".*<h1>.*New in Version (.*)</h1>.*");

        if ( !isnull(version[1]) ) {
          vers=version[1];
          concUrl = url;
        }
      }
    }

    set_kb_item(name: "mambo_cms/detected", value: TRUE);

    cpe = build_cpe(value:vers, exp:"^([0-9.]+([a-z0-9]+)?)", base:"cpe:/a:mambo-foundation:mambo:");
    if(!cpe)
      cpe = 'cpe:/a:mambo-foundation:mambo';

    register_product(cpe: cpe, location: install, port: port, service: "www");

    log_message(data: build_detection_report(app: "Mambo CMS", version: vers, install: install, cpe: cpe,
                                             concluded: version[0], concludedUrl: concUrl),
                port: port);
    exit(0);
  }
}

exit(0);
