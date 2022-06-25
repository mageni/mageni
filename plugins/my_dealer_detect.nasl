###############################################################################
# OpenVAS Vulnerability Test
# $Id: my_dealer_detect.nasl 12962 2019-01-08 07:46:53Z ckuersteiner $
#
# My Dealer CMS Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.100138");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 12962 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-08 08:46:53 +0100 (Tue, 08 Jan 2019) $");
  script_tag(name:"creation_date", value:"2009-04-16 19:20:22 +0200 (Thu, 16 Apr 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("My Dealer CMS Detection");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"This host is running My Dealer CMS, a advanced dealer manager software.");

  script_xref(name:"URL", value:"http://www.mydealercms.biz");
  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!can_host_php(port:port))exit(0);

foreach dir( make_list_unique( "/cms", cgi_dirs( port:port ) ) ) {
 install = dir;
 if( dir == "/" ) dir = "";

 url = dir + "/index.php";
 buf = http_get_cache( item:url, port:port );
 if( buf == NULL ) continue;

 if(egrep(pattern: '<META content="MyDealer Cms" name=GENERATOR>', string: buf, icase: TRUE) ||
    egrep(pattern: 'Powered by: <a href="http://www.mydealercms.biz">My Dealer Cms', string: buf, icase: TRUE)) {
    vers = "unknown";

    version = eregmatch(string: buf, icase:TRUE,
                        pattern: 'Powered by: <a href="http://www.mydealercms.biz">My Dealer Cms ([0-9.]+)</a>');

    if ( !isnull(version[1]) )
       vers = version[1];

    set_kb_item(name: "mydealercms/detected", value: TRUE);

    cpe = build_cpe(value: vers, exp: "^([0-9.]+)", base: "cpe:/a:mydealercms:mydealercms:");
    if (!cpe)
      cpe = 'cpe:/a:mydealercms:mydealercms';

    register_product(cpe: cpe, location: install, port: port, service: "www");

    log_message(data: build_detection_report(app: "MyDealer CMS", version: version, install: install, cpe: cpe,
                                             concluded: version[0]),
                port: port);
    exit(0);
  }
}

exit(0);
