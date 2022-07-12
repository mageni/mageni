###############################################################################
# OpenVAS Vulnerability Test
#
# Photopost Detection
#
# Authors:
# LSS Security Team <http://security.lss.hr>
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 LSS <http://www.lss.hr> / Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.100285");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2019-05-13T14:05:09+0000");
  script_tag(name:"last_modification", value:"2019-05-13 14:05:09 +0000 (Mon, 13 May 2019)");
  script_tag(name:"creation_date", value:"2009-10-02 19:48:14 +0200 (Fri, 02 Oct 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Photopost Detection");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2009 LSS / Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"This host is running Photopost, a photo sharing gallery software.");
  script_xref(name:"URL", value:"http://www.photopost.com/");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

SCRIPT_DESC = "Photopost Detection";

port = get_http_port(default:80);
if(!can_host_php(port:port))exit(0);

foreach dir( make_list_unique( "/photopost", "/photos", "/gallery", "/photo", cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" ) dir = "";
  url = dir + "/index.php";
  buf = http_get_cache( item:url, port:port );
  if(!buf) continue;

  match=egrep(pattern:'Powered by[^>]*>(<font[^>]*>)?PhotoPost',string:buf, icase:TRUE);
  if(match) {
    match=egrep(pattern:'Powered by[^>]*>(<font[^>]*>)?PhotoPost.*PHP ([0-9.a-z]+)',string:buf, icase:TRUE);
    if(match)
      item=eregmatch(pattern:'Powered by[^>]*>(<font[^>]*>)?PhotoPost.*PHP ([0-9.a-z]+)',string:match, icase:TRUE);
    ver=item[2];

    if(!ver) ver="unknown";

    tmp_version = string(ver, " under ", install);
    set_kb_item(name:string("www/", port, "/photopost"),value:tmp_version);
    set_kb_item(name:"photopost/detected", value:TRUE);

    cpe = build_cpe(value:tmp_version, exp:"^([0-9.]+([a-z0-9]+)?)", base:"cpe:/a:photopost:photopost_php_pro:");
    if(!isnull(cpe))
       register_host_detail(name:"App", value:cpe, desc:SCRIPT_DESC);

    info+=ver + " under " + install + '\n';
    n++;
  }
}

if(!n) exit(0);

info="The following version(s) of PhotoPost were detected: " + '\n\n'+info;
log_message(port:port, data:info);
exit(0);
