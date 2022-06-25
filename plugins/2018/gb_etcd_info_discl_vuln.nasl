##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_etcd_info_discl_vuln.nasl 9209 2018-03-27 02:21:30Z ckuersteiner $
#
# etcd Information Disclosure Vulnerability
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

CPE = "cpe:/a:coreos:etcd";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140888");
  script_version("$Revision: 9209 $");
  script_tag(name: "last_modification", value: "$Date: 2018-03-27 04:21:30 +0200 (Tue, 27 Mar 2018) $");
  script_tag(name: "creation_date", value: "2018-03-27 08:55:55 +0700 (Tue, 27 Mar 2018)");
  script_tag(name: "cvss_base", value: "5.0");
  script_tag(name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_tag(name: "qod_type", value: "exploit");

  script_tag(name: "solution_type", value: "Workaround");

  script_name("etcd Information Disclosure Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_etcd_detect.nasl");
  script_mandatory_keys("etcd/installed");

  script_tag(name: "summary", value: "etcd is prone to an information disclosure vulnerability if no authentication
is enabled. An attacker may read all stored key values which might contain sensitive information like passwords.");

  script_tag(name: "vuldetect", value: "Sends a crafted HTTP GET requst and checks the response.");

  script_tag(name: "impact", value: "An unauthenticated attacker may gather sensitive information which could lead
to further attacks.");

  script_tag(name: "solution", value: "Enable authentication (see https://coreos.com/etcd/docs/latest/v2/authentication.html)");

  script_xref(name: "URL", value: "https://elweb.co/the-security-footgun-in-etcd/");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!get_app_location(cpe: CPE, port: port, nofork: TRUE))
  exit(0);

url = '/v2/keys/?recursive=true';
req = http_get(port: port, item: url);
res = http_keepalive_send_recv(port: port, data: req);

if (res =~ "^HTTP/1\.[01] 200" && '{"action":"get"' >< res) {
  expert_info = 'Response:\n' + res;
  report = report_vuln_url(port: port, url: url);
  security_message(port: port, data: report, expert_info: expert_info);
  exit(0);
}

exit(99);
