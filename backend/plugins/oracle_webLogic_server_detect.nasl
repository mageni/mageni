###############################################################################
# OpenVAS Vulnerability Test
#
# Oracle WebLogic Server Detection
#
# Authors:
# Michael Meyer
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
  script_oid("1.3.6.1.4.1.25623.1.0.100493");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2019-05-06T10:32:17+0000");
  script_tag(name:"last_modification", value:"2019-05-06 10:32:17 +0000 (Mon, 06 May 2019)");
  script_tag(name:"creation_date", value:"2010-02-14 12:35:00 +0100 (Sun, 14 Feb 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Oracle WebLogic Server Detection");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 7001);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detection of Oracle WebLogic Server.

  The script sends a connection request to the server and attempts to extract the version number from the reply.");

  script_xref(name:"URL", value:"https://www.oracle.com/middleware/weblogic/");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

port = get_http_port(default: 7001);
banner = get_http_banner(port: port);

if (banner =~ "Server: WebLogic ") {
  version = "unknown";
  servicepack = "unknown";

  # Server: WebLogic Server 7.0 SP5 Wed Mar 31 23:12:50 PST 2004 363281
  # Server: Weblogic 12.2.1.1
  # Server: WebLogic Server 10.3.6.0.171017 PSU Patch for BUG26519424 TUE SEP 12 18:34:42 IST 2017
  # Server: WebLogic 5.1.0 Service Pack 6 09/20/2000 21:03:19 #84511
  # Server: WebLogic WebLogic Server 6.1 SP2  12/18/2001 11:13:46 #154529
  vers = eregmatch(pattern: "WebLogic (Server )?([0-9.]+)( (SP|Service Pack )([0-9]+))?", string: banner,
         icase: TRUE);
  if (!isnull(vers[2])) {
    version = vers[2];
    url = "/";
    if (!isnull(vers[5]))
      servicepack = vers[5];
  }
}
else {
  url = "/console/login/LoginForm.jsp";

  buf = http_get_cache(item: url, port: port);

  if (buf && ("<title>Oracle WebLogic Server Administration Console" >< buf ||
      egrep(pattern: "<TITLE>WebLogic Server.*Console Login", string: buf))) {
    version = "unknown";
    servicepack = "unknown";

    vers = eregmatch(string: buf, pattern: "WebLogic Server ([0-9.]+)", icase: TRUE);
    if (!isnull(vers[1])){
      version = vers[1];
    }
    else {
      vers = eregmatch(string: buf, pattern: "WebLogic Server Version: ([0-9.]+)", icase: TRUE);
      if (!isnull(vers[1]))
        version = vers[1];
    }
  }
  else
    exit(0);
}

found_services = FALSE;
found_services_urls = make_list();

endpoints = make_array(
"/_async/AsyncResponseService?WSDL", "www\.bea\.com/async/AsyncResponseService",
"/_async/AsyncResponseServiceHttps?WSDL", "www\.bea\.com/async/AsyncResponseService",
"/_async/AsyncResponseServiceJms?WSDL", "www\.bea\.com/async/AsyncResponseService",
"/_async/AsyncResponseServiceSoap12?WSDL", "www\.bea\.com/async/AsyncResponseService",
"/_async/AsyncResponseServiceSoap12Https?WSDL", "www\.bea\.com/async/AsyncResponseService",
"/_async/AsyncResponseServiceSoap12Jms?WSDL", "www\.bea\.com/async/AsyncResponseService",
"/wls-wsat/CoordinatorPortType", "weblogic\.wsee\.wstx\.wsat\.v1[01]\.endpoint\.CoordinatorPort",
"/wls-wsat/CoordinatorPortType11", "weblogic\.wsee\.wstx\.wsat\.v1[01]\.endpoint\.CoordinatorPort",
"/wls-wsat/ParticipantPortType", "weblogic\.wsee\.wstx\.wsat\.v1[01]\.endpoint\.ParticipantPort",
"/wls-wsat/ParticipantPortType11", "weblogic\.wsee\.wstx\.wsat\.v1[01]\.endpoint\.ParticipantPort",
"/wls-wsat/RegistrationPortTypeRPC", "weblogic\.wsee\.wstx\.wsc\.v1[01]\.endpoint\.RegistrationPort",
"/wls-wsat/RegistrationRequesterPortType", "weblogic\.wsee\.wstx\.wsc\.v1[01]\.endpoint\.RegistrationRequesterPort",
"/wls-wsat/RegistrationPortTypeRPC11", "weblogic\.wsee\.wstx\.wsc\.v1[01]\.endpoint\.RegistrationPort");

foreach endpoint (keys(endpoints)) {

  check = endpoints[endpoint];

  req = http_get(port: port, item: endpoint);
  res = http_keepalive_send_recv(port: port, data: req, bodyonly: TRUE);

  if (res && eregmatch(string: res, pattern: check, icase: FALSE)) {
    found_services = TRUE;
    found_services_urls = make_list(found_services_urls, report_vuln_url(port: port, url: endpoint, url_only: TRUE));
  }
}

conclurl = report_vuln_url(port: port, url: url, url_only: TRUE);

set_kb_item(name: "OracleWebLogicServer/installed", value: TRUE);

CPE1 = "cpe:/a:bea:weblogic_server";
CPE2 = "cpe:/a:oracle:weblogic_server";
if (version != "unknown") {
  CPE1 += ":" + version;
  CPE2 += ":" + version;

  if (servicepack != "unknown") {
    CPE1 += ":sp" + servicepack;
    CPE2 += ":sp" + servicepack;
    version += " SP" + servicepack;
  }
}

register_product(cpe: CPE1, location: "/", port: port, service: "www");
register_product(cpe: CPE2, location: "/", port: port, service: "www");

report = build_detection_report(app: "Oracle WebLogic Server", version: version, install: "/", cpe: CPE1,
                                concluded: vers[0], concludedUrl: conclurl);

if (found_services) {
  report += '\n\nThe following Web-Services have been identified:\n';
  found_services_urls = sort(found_services_urls);
  foreach found_services_url(found_services_urls)
    report += '\n' + found_services_url;
}

log_message(data: report, port: port);
exit(0);
