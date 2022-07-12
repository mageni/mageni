# OpenVAS Vulnerability Test
# $Id: basilix_detect.nasl 11028 2018-08-17 09:26:08Z cfischer $
# Description: BasiliX Detection
#
# Authors:
# George A. Theall, <theall@tifaware.com>
#
# Copyright:
# Copyright (C) 2004 George A. Theall
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.14308");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11028 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-17 11:26:08 +0200 (Fri, 17 Aug 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("BasiliX Detection");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2004 George A. Theall");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://sourceforge.net/projects/basilix/");

  script_tag(name:"summary", value:"The remote web server contains a webmail application written in PHP.

  Description :

  This script detects whether the remote host is running BasiliX and extracts version numbers and locations of any
  instances found.

  BasiliX is a webmail application based on PHP and IMAP and powered by MySQL.");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);

installs = 0;
foreach dir( make_list_unique( "/basilix", cgi_dirs( port:port ) ) ) {
  install = dir;
  if (dir == "/")
    dir = "";

  url = string(dir, "/basilix.php");
  if (port == 443) url = string(url, "?is_ssl=1");

  req = string(
    "GET ",  url, " HTTP/1.1\r\n",
    "Host: ", get_host_name(), "\r\n",
    "Cookie: BSX_TestCookie=yes\r\n",
    "\r\n"
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
  if (res == NULL) exit(0);

  if ("BasiliX" >< res) {
    # Search for the version string in a couple of different places.
    #
    # - it's usually in the HTML title element.
    title = strstr(res, "<title>");
    if (title != NULL) {
      title = title - strstr(title,string("\n"));
      pat = "BasiliX (.+)</title>";
      ver = eregmatch(pattern:pat, string:title, icase:TRUE);
      if (ver != NULL) ver = ver[1];
    }
    # - otherwise, look at the "generator" meta tag.
    if (isnull(ver)) {
      generator = strstr(res, '<meta name="generator"');
      if (generator != NULL) {
        generator = generator - strstr(generator, string("\n"));
        pat = 'content="BasiliX (.+)"';
        ver = eregmatch(pattern:pat, string:generator, icase:TRUE);
        if (ver != NULL) ver = ver[1];
      }
    }
    # - last try, older versions include it in the copyright notice.
    if (isnull(ver)) {
      copyright = strstr(res, "BasiliX v");
      if (copyright != NULL) {
        copyright = copyright - strstr(copyright, string("\n"));
        pat = "BasiliX v(.+) -- &copy";
        ver = eregmatch(pattern:pat, string:copyright, icase:TRUE);
        if (ver != NULL) ver = ver[1];
      }
    }

    set_kb_item(name: "basilix/installed", value: TRUE);

    # Handle reporting
    if (!isnull(ver)) {
      tmp_version = string(ver, " under ", dir);
      set_kb_item(name:string("www/", port, "/basilix"), value:tmp_version);

        cpe = build_cpe(value:tmp_version, exp:"^([0-9.]+\.[0-9])\.?([a-z0-9]+)?", base:"cpe:/a:basilix:basilix_webmail:");
        if (!cpe)
           cpe = 'cpe:/a:basilix:basilix_webmail';

      register_product(cpe: cpe, location: install, port: port);

      installations[dir] = ver;
      ++installs;
    }

    if (installs) break;
  }
}


# Report any instances found
if (installs) {
  if (installs == 1) {
    foreach dir (keys(installations)) {
      # empty - just need to set 'dir'.
    }
    info = string("BasiliX ", ver, " was detected on the remote host under the path ", dir, ".");
  }
  else {
    info = string(
      "Multiple instances of BasiliX were detected on the remote host:\n",
      "\n"
    );
    foreach dir (keys(installations)) {
      info = info + string("    ", installations[dir], ", installed under ", dir, "\n");
    }
    info = chomp(info);
  }

  log_message(port:port, data:info);
  exit(0);
}

exit(0);
