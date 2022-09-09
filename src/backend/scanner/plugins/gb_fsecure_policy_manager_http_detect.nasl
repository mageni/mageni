# Copyright (C) 2022 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.148658");
  script_version("2022-09-07T10:10:59+0000");
  script_tag(name:"last_modification", value:"2022-09-07 10:10:59 +0000 (Wed, 07 Sep 2022)");
  script_tag(name:"creation_date", value:"2022-09-01 08:40:13 +0000 (Thu, 01 Sep 2022)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("F-Secure Policy Manager Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of F-Secure Policy Manager (Server, Proxy
  and Web Reporting).");

  script_xref(name:"URL", value:"https://www.withsecure.com/us-en/solutions/software-and-services/business-suite/policy-manager");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 443);

# nb:
# - For Server and Proxy in current versions
# - In a VT from 2011 this was also the detection point for Web Reporting
url1 = "/";
res1 = http_get_cache(port: port, item: url1);

# nb: For newer versions of Web Reporting
url2 = "/login";
res2 = http_get_cache(port: port, item: url2);

# <title>F-Secure Policy Manager Web Reporting</title>
# <title>F-Secure Policy Manager Server</title>
# <title>F-Secure Policy Manager Proxy</title>
if (("<title>F-Secure Policy Manager" >< res1 && 'alt="Policy Manager"' >< res1) ||
    ('<img src="/images/frame/product-title-policy-manager.png"' >< res1 && 'alt="F-Secure"/>' >< res1) ||
    (">Proxy is installed and working fine.<" >< res1 && ">F-Secure Corporation<" >< res1) ||
    "<span>If you see this message, F-Secure Policy Manager Server is installed and is working fine.</span>" >< res1 ||
    ("<title>F-Secure Policy Manager Web Reporting" >< res2 && "We're sorry but reporting doesn't work properly without JavaScript enabled. Please enable it to continue." >< res2) ||
    # nb: See note above
    ">F-Secure Policy Manager Web Reporting<" >< res1
   ) {

  install = "/";
  version = "unknown";
  app_name = "F-Secure Policy Manager";
  base_cpe = "cpe:/a:f-secure:policy_manager";

  # nb: Generic KB key for both products
  set_kb_item(name: "fsecure/policy_manager/detected", value: TRUE);
  set_kb_item(name: "fsecure/policy_manager/http/detected", value: TRUE);

  if (">Proxy is installed and working fine.<" >< res1 || "F-Secure Policy Manager Proxy" >< res1) {
    app_name += " Proxy";
    base_cpe += "_proxy";
    set_kb_item(name: "fsecure/policy_manager/proxy/detected", value: TRUE);
    set_kb_item(name: "fsecure/policy_manager/proxy/http/detected", value: TRUE);
    concUrl = http_report_vuln_url(port: port, url: url1, url_only: TRUE);
  } else if ("F-Secure Policy Manager Server" >< res1) {
    app_name += " Server";
    base_cpe += "_server";
    set_kb_item(name: "fsecure/policy_manager/server/detected", value: TRUE);
    set_kb_item(name: "fsecure/policy_manager/server/http/detected", value: TRUE);
    concUrl = http_report_vuln_url(port: port, url: url1, url_only: TRUE);
  } else if ("F-Secure Policy Manager Web Reporting" >< res2 || "F-Secure Policy Manager Web Reporting" >< res1) {
    app_name += " Web Reporting";
    base_cpe += "_web_reporting";
    set_kb_item(name: "fsecure/policy_manager/web_reporting/detected", value: TRUE);
    set_kb_item(name: "fsecure/policy_manager/web_reporting/http/detected", value: TRUE);
    if ("F-Secure Policy Manager Web Reporting" >< res2)
      concUrl = http_report_vuln_url(port: port, url: url2, url_only: TRUE);
    else
      concUrl = http_report_vuln_url(port: port, url: url1, url_only: TRUE);
  }

  # nb: This works for both, Proxy and Server. Note that the Proxy one has also the following in
  # the HTML source code of the "/" page:
  #
  # <div class="proxy-status">
  # <span class="title">Proxy is installed and working fine.</span>
  # <br>
  # <span class="secondary">Version: 15.30.96312</span>
  # <br>
  # <span class="secondary">Mode: Forward</span>
  # </div>
  #
  # nb: On Web Reporting this seems to be not available.
  #
  # nb: An older VT from 2008/fs_policy_manager_7_dos.nasl had used this already so this
  # endpoint seems to exist since quite some time...

  url = "/fsms/fsmsh.dll?FSMSCommand=GetVersion";

  res = http_get_cache(port: port, item: url);
  if (res && res =~ "^HTTP/1\.[01] 200") {
    body = http_extract_body_from_response(data: res);

    # nb: Only this with a leading \r\n:
    # 15.10.94031
    vers = eregmatch(pattern: "..([0-9.]{3,})$", string: chomp(body));
    if (!isnull(vers[1])) {
      version = vers[1];
      if (concUrl)
        concUrl += '\n';
      concUrl += http_report_vuln_url(port: port, url: url, url_only: TRUE);
    }
  }

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: base_cpe + ":");
  if (!cpe)
    cpe = base_cpe;

  register_product(cpe: cpe, location: install, port: port, service: "www");

  log_message(data: build_detection_report(app: app_name, version: version, install: install,
                                           cpe: cpe, concluded: vers[0], concludedUrl: concUrl),
              port: port);
}

exit(0);
