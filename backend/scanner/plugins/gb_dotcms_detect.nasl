###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dotcms_detect.nasl 11458 2018-09-18 13:10:59Z jschulte $
#
# dotCMS Detection
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106114");
  script_version("$Revision: 11458 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-18 15:10:59 +0200 (Tue, 18 Sep 2018) $");
  script_tag(name:"creation_date", value:"2016-07-05 08:55:18 +0700 (Tue, 05 Jul 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("dotCMS Detection");

  script_tag(name:"summary", value:"Detection of dotCMS

  The script sends a connection request to the server and attempts to detect the presence of dotCMS and to
  extract its version");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://dotcms.com");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

port = get_http_port(default: 80);

foreach dir (make_list_unique("/", "/dotcms", "/dotCMS", "/dotAdmin", cgi_dirs(port: port))) {
  install = dir;
  if (dir == "/")
    dir = "";

  foreach url (make_list_unique(dir + "/html/portal/login.jsp", dir + "/application/login/login.html")) {
    found = FALSE;
    version = "unknown";

    res = http_get_cache(port: port, item: url);

    # detection < 4.0.0
    if (res =~ "^HTTP/1.. 200 OK" && "<title>dotCMS : Enterprise Web Content Management</title>" >< res &&
        "modulePaths: { dotcms:" >< res) {
      found = TRUE;

      # The version length differs between 7, 5 and 3 characters (e.g. '1.9.5.1', '2.3.2', '3.3')
      # Its identification gets significantly improved, if the specific length is being declared inside the
      # regular expression pattern
      for (i = 7; i > 0; i -= 2) {
        ver = eregmatch(pattern: "<br />.*(COMMUNITY|ENTERPRISE) (EDITION|PROFESSIONAL).*([0-9\.]{" + i + "})<br/>", string: res);
        if (!isnull(ver[3])) {
          version = ver[3];
          concUrl = url;
          break;
        }
      }

      # Version info might be appended to .css, .js and/or .jsp files
      if (version == "unknown") {
          ver = eregmatch(pattern: '\\.(css|js|jsp)\\?b=([0-9\\.]+)\\";', string: res);
          version = ver[2];
          concUrl = url;
      }
    }

    # detection >= 4.0.0
    if (res =~ "^HTTP/1.. 200 OK" && ("dotcms" >< res || "dotCMS" >< res) &&
        ('<meta name="application-name" content="dotCMS dotcms.com"' >< res ||
          "document.getElementById('macro-login-user-name').value = 'bill@dotcms.com';" >< res ||
          '<link rel="stylesheet" href="/DOTLESS/application/themes/quest/less/main.css">' >< res ||
          '<link rel="shortcut icon" href="http://dotcms.com/favicon.ico" type="image/x-icon">' >< res ||
          'href="http://dotcms.com/plugins/single-sign-on-using-oauth2"' >< res ||
          'Powered by dotCMS' >< res ||
          '<a class="dropdown-item" href="/dotCMS/logout"' >< res)
       ) {
      found = TRUE;

      # Admin Login is on /dotAdmin which makes a POST call to /api/v1/loginform for the version et al.
      url = '/api/v1/loginform';

      data = '{"messagesKey":["Login","email-address","user-id","password","remember-me","sign-in",' +
             '"get-new-password","cancel","Server","error.form.mandatory",' +
             '"angular.login.component.community.licence.message","reset-password-success",' +
             '"a-new-password-has-been-sent-to-x"],"language":"","country":""}';

      req = http_post_req(port: port, url: url, data: data,
                          add_headers: make_array("Content-Type", "application/json"));
      res = http_keepalive_send_recv(port: port, data: req);

      ver = eregmatch(pattern: '"version":"([0-9.]+)', string: res);
      if (!isnull(ver[1]))
        version = ver[1];
        concUrl = url;
    }

    if (found) {
      set_kb_item(name: "dotCMS/installed", value: TRUE);

      if (version != "unknown") {
        set_kb_item(name: "dotCMS/version", value: version);
      }

#      concUrl = report_vuln_url(port: port, url: url, url_only: TRUE);

      cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:dotcms:dotcms:");
      if (isnull(cpe))
        cpe = "cpe:/a:dotcms:dotcms";

      register_product(cpe: cpe, location: install, port: port);

      log_message(data: build_detection_report(app: "dotCMS", version: version, install: install, cpe: cpe,
                                             concluded: ver[0], concludedUrl: concUrl),
                  port: port);
      exit(0);
    }
  }

  # detection >= 5.0.0
  foreach location(make_list_unique("/", "/api", "/api/v1", "/api/v2", "/api/v3", cgi_dirs(port: port))) {
    dir = location;
    if(dir == "/")
      dir = "";
    url = dir + "/appconfiguration";
    buf = http_get_cache(item: url, port: port);
    if( buf =~ 'dotcms.websocket' ) {
      set_kb_item(name: "dotCMS/installed", value: TRUE);

      version = "unknown";
      ver = eregmatch(string: buf, pattern: '"version":"([0-9.]+)"', icase: TRUE);
      if(!isnull(ver[1])) {
        version = ver[1];
        set_kb_item(name: "dotCMS/version", value: version);
      }

      register_and_report_cpe(app: "dotCMS",
                              ver: version,
                              concluded: ver[0],
                              base: "cpe:/a:dotcms:dotcms:",
                              expr: '([0-9.]+)',
                              insloc: location,
                              regPort: port,
                              conclUrl: url);

      exit(0);
    }
  }
}

exit(0);
