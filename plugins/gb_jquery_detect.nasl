###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_jquery_detect.nasl 14001 2019-03-05 15:06:57Z cfischer $
#
# jQuery Detection
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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
  script_oid("1.3.6.1.4.1.25623.1.0.141622");
  script_version("$Revision: 14001 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-05 16:06:57 +0100 (Tue, 05 Mar 2019) $");
  script_tag(name:"creation_date", value:"2018-11-01 09:53:59 +0700 (Thu, 01 Nov 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("jQuery Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://jquery.com/");

  script_tag(name:"summary", value:"Detection of jQuery.

  The script sends a connection request to the server and attempts to detect jQuery and to extract its version.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

function extract_jquery_location( jquerydir, jqueryfile, basedir ) {

  local_var jquerydir, jqueryfile, basedir;
  local_var ret_array, location, fullurl;

  ret_array = make_array();

  if (!isnull(jquerydir)) {
    if (jquerydir !~ "^/" && jquerydir !~ "^\./")
      location = basedir + "/" + jquerydir;
    else if (jquerydir =~ "^\./")
      location = ereg_replace(string: jquerydir, pattern: "^(\./)", replace: basedir + "/");
    else if (detect[1] =~ "^/")
      location = jquerydir;
    else
      location = basedir + jquerydir;
  } else {
    if (jquerydir !~ "^/" && jquerydir !~ "^\./")
      location = basedir;
    else if (jquerydir =~ "^\./")
      location = ereg_replace(string: jquerydir, pattern: "^(\./)", replace: basedir + "/");
    else
      location = basedir;
  }

  if (location != "/")
    location = ereg_replace( string:location, pattern:"(/)$", replace:"" );

  if (jqueryfile !~ "^/")
    jqueryfile = "/" + jqueryfile;

  ret_array["location"] = location;

  if (location == "/")
    ret_array["fullurl"] = jqueryfile;
  else
    ret_array["fullurl"] = location + jqueryfile;

  return ret_array;
}

pattern = 'src=["\']([^ ]*)(jquery[-.]?([0-9.]+)?(\\.(min|slim|slim\\.min)?)\\.js)';
detected_urls = make_list();

port = get_http_port(default: 80);

foreach dir (make_list_unique("/", cgi_dirs(port: port))) {

  install = dir;
  if (dir == "/")
    dir = "";

  res = http_get_cache(port: port, item: dir + "/");
  detect = eregmatch(pattern: pattern, string: res);
  if (! detect)
    continue;

  version = "unknown";
  extra   = "";

  # src="js/get_scripts.js.php?scripts%5B%5D=jquery/jquery-2.1.4.min.js
  # src="js/jquery-1.8.2.min.js"
  # src="jquery-1.8.2.min.js"
  # src="/jquery-1.8.2.min.js"
  # src="/pub/jquery-1.11.2.min.js"
  # src="./js/jquery-1.11.2.min.js"
  # src="https://code.jquery.com/jquery-3.2.1.slim.min.js"
  #
  # Uncommon, but seems to be sometimes used: https://community.greenbone.net/t/false-positive-jquery-1-9-0-xss-vulnerability/1683
  # src="/js/jquery.2.2.1.min.js"
  # src="/scripts/lib/jquery1.11.2.js"
  #
  # TODO: Gather version from e.g.:
  # src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.3.1/jquery.min.js"
  if (!isnull(detect[3])) {
    vers = eregmatch(pattern: "([0-9.]+)", string: detect[3]);
    if (!isnull(vers[1]))
      version = vers[1];

    infos = extract_jquery_location(jquerydir: detect[1], jqueryfile: detect[2], basedir: dir);
    location = infos["location"];
    if (!location)
      location = "unknown";

    if (in_array(search: location, array: detected_urls, part_match: FALSE))
      continue;

    detected_urls = make_list(detected_urls, location);

    set_kb_item(name: "jquery/detected", value: TRUE);

    cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:jquery:jquery:");
    if (!cpe)
      cpe = "cpe:/a:jquery:jquery";

    register_product(cpe: cpe, location: location, port: port, service: "www");

    log_message(data: build_detection_report(app: "jQuery", version: version, install: location, cpe: cpe,
                                             concluded: detect[0]),
                port: port);
  }

  # src="/imports/jquery/dist/jquery.slim.min.js"
  # src="scripts/jquery.min.js"
  # src="jquery.min.js"
  # src="/jquery.min.js"
  # src="/vendor/jquery/dist/jquery.min.js?v=ee993990e91701d6096efd4e9817ec7d"
  # src="./assets/javascript/jquery.min.js?assets_version=411"
  else if (!isnull(detect[2])) {

    infos = extract_jquery_location( jquerydir:detect[1], jqueryfile:detect[2], basedir:dir );
    location = infos["location"];
    url = infos["fullurl"];
    if (!location)
      location = "unknown";

    # nb: Hosted on a different server. On such environments we can't query the version by direct
    # access but still want to report the use of jquery without extracting the version.
    #
    # src="https://ajax.googleapis.com/ajax/libs/jquery/1/jquery.min.js"
    #
    # nb: The following is interpreted by the browser as an URL where the protocol (https or http) is prepended.
    # src="//ajax.googleapis.com/ajax/libs/jquery/1/jquery.min.js"
    #
    if (detect[1] !~ "^http(s)?://" && detect[1] !~ "^//") {
      req = http_get(port: port, item: url);
      res = http_keepalive_send_recv(port: port, data: req);

      # /*! jQuery v1.9.1 | (c) 2005, 2012 jQuery Foundation, Inc. | jquery.org/license
      # /*! jQuery v2.1.4 | (c) 2005, 2015 jQuery Foundation, Inc. | jquery.org/license */
      # /*! jQuery v1.12.4 | (c) jQuery Foundation | jquery.org/license */
      vers = eregmatch(pattern: "jQuery v([0-9.]+)", string: res);
      if (!isnull(vers[1])) {
        version = vers[1];
        concl   = vers[0];
        concUrl = url;
      }
    } else {
      extra  = "The jQuery library is hosted on a different server. Because of this it is not possible to gather the ";
      extra += "version by a direct file access. Please manually inspect the version which gets included on this web page.";
      location = "Externally hosted";
      concl = detect[0] + " embedded into URL " + install;
    }

    if (in_array(search: location, array: detected_urls, part_match: FALSE))
      continue;

    detected_urls = make_list(detected_urls, location);

    set_kb_item(name: "jquery/detected", value: TRUE);

    cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:jquery:jquery:");
    if (!cpe)
      cpe = "cpe:/a:jquery:jquery";

    register_product(cpe: cpe, location: location, port: port, service: "www");

    log_message(data: build_detection_report(app: "jQuery", version: version, install: location, cpe: cpe,
                                             concluded: concl, concludedUrl: concUrl, extra: extra),
                port: port);
  }
}

exit(0);