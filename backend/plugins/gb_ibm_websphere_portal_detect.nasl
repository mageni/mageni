###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_websphere_portal_detect.nasl 13679 2019-02-15 08:20:11Z cfischer $
#
# IBM WebSphere Portal Detection
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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
  script_oid("1.3.6.1.4.1.25623.1.0.106198");
  script_version("$Revision: 13679 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-15 09:20:11 +0100 (Fri, 15 Feb 2019) $");
  script_tag(name:"creation_date", value:"2016-08-24 14:38:56 +0700 (Wed, 24 Aug 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("IBM WebSphere Portal Detection");

  script_tag(name:"summary", value:"Detection of IBM WebSphere Portal

  The script sends a connection request to the server and attempts to detect the presence of IBM WebSphere Portal
  and to extract its version");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www-03.ibm.com/software/products/en/websphere-portal-family");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

port = get_http_port(default: 443);

url = "/wps/portal/Home/Welcome/";
req = http_get(port: port, item: url);
res = http_keepalive_send_recv(port: port, data: req);

# Handle 30x returns: we want to follow them
if (res =~ "^HTTP/1.. 30.") {
  loc = http_extract_location_from_redirect(port: port, data: res);
  if (loc) {
    cookie = eregmatch(pattern: "Set-Cookie: (DigestTracker=[A-Za-z;]+)", string: res);
    if (!isnull(cookie[1]))
      req = http_get_req(port: port, url: loc, add_headers: make_array("Cookie", cookie[1]));
    else
      req = http_get(port: port, item: loc);
    res = http_keepalive_send_recv(port: port, data: req);
  }
}

if ("IBM WebSphere Portal" >< res) {
  version = "unknown";

  req = http_get(port: port, item: "/wps/contenthandler/wcmrest/ProductVersion/");
  res = http_keepalive_send_recv(port: port, data: req);

  # Handle 30x returns: we want to follow them
  if (res =~ "^HTTP/1.. 30.") {
    loc = eregmatch(pattern: "Location: (.*\/wcmrest\/ProductVersion\/)", string: res);
    if(!isnull(loc[1])) {
      url = loc[1];
      req = http_get(port: port, item: url);
      res = http_keepalive_send_recv(port: port, data: req, bodyonly: TRUE);

      if ("<major>" >< res && "<fix-level>" >< res) {
        concl = res;
        major = eregmatch(pattern: "<major>([0-9]+)</major>", string: res);
        minor = eregmatch(pattern: "<minor>([0-9]+)</minor>", string: res);
        maint = eregmatch(pattern: "<maintenance>([0-9]+)</maintenance>", string: res);
        minmaint = eregmatch(pattern: "<minor-maintenance>([0-9]+)</minor-maintenance>", string: res);
        fixlevel = eregmatch(pattern: "<fix-level>([0-9]+)</fix-level>", string: res);
        if (!isnull(major[1]) && !isnull(minor[1]) && !isnull(maint[1]) && !isnull(minmaint[1]) &&
            !isnull(fixlevel[1]))
          version = major[1] + '.' + minor[1] + '.' + maint[1] + '.' + minmaint[1] + '.' + fixlevel[1];
      }
    }
  }

  set_kb_item(name: "ibm_websphere_portal/installed", value: TRUE);
  if (version != "unknown")
    set_kb_item(name: "ibm_websphere_portal/installed", value: version);

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:ibm:websphere_portal:");
  if (!cpe)
      cpe = 'cpe:/a:ibm:websphere_portal';

  register_product(cpe: cpe, location: "/", port: port);

  log_message(data: build_detection_report(app: "IBM WebSphere Portal", version: version, install: "/",
                                           cpe: cpe, concluded: concl),
              port: port);
  exit(0);
}

exit(0);
