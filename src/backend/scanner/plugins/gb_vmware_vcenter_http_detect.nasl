# Copyright (C) 2013 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.103659");
  script_version("2021-03-26T11:18:40+0000");
  script_tag(name:"last_modification", value:"2021-03-30 10:22:27 +0000 (Tue, 30 Mar 2021)");
  script_tag(name:"creation_date", value:"2013-02-06 17:30:38 +0100 (Wed, 06 Feb 2013)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("VMware vCenter Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of VMware vCenter.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("port_service_func.inc");

port = http_get_port(default:443);
host = http_host_name(port:port);

soc = open_sock_tcp(port);
if(!soc)
  exit(0);

req  = string("GET / HTTP/1.1\r\n");
req += string("Host: ", host, "\r\n\r\n");

send(socket:soc, data:req);
buf = recv(socket:soc, length:8192);
close(soc); # needed for the strange behaviour of esx 3.x

if(!buf || "VMware" >!< buf)
  exit(0);

soc = open_sock_tcp(port);
if(!soc)
  exit(0);

version = "unknown";
build = "unknown";

url = "/sdk";
req  = string("POST ", url, " HTTP/1.1\r\n");
req += string("Host: ", host, "\r\n");
req += string("Content-Type: application/x-www-form-urlencoded\r\n");
req += string("Content-Length: 348\r\n\r\n");
req += string('
<env:Envelope xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:env="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
\t\t\t<env:Body>
\t\t\t<RetrieveServiceContent xmlns="urn:vim25">
\t\t\t\t<_this type="ServiceInstance">ServiceInstance</_this>
\t\t\t</RetrieveServiceContent>
\t\t\t</env:Body>
</env:Envelope>');
req += string("\r\n");

send(socket:soc, data:req);
buf = recv(socket:soc, length:8192);
close(soc);

if(!buf || "RetrieveServiceContentResponse" >!< buf ||
   "<fullName>VMware vCenter Server" >!< buf)
  exit(0);

set_kb_item(name:"vmware/vcenter/http/" + port + "/concludedUrl",
            value:http_report_vuln_url(port:port, url:url, url_only:TRUE));

# <version>6.5.0</version>
vers = eregmatch(pattern:"<version>([0-9.]+)</version>", string:buf);
if(!isnull(vers[1]))
  version = vers[1];

# <build>7070488</build>
bld = eregmatch(pattern:"<build>([0-9]+)</build>", string:buf);
if(!isnull(bld[1])) {
  build =  bld[1];
}

r = eregmatch(pattern:"<returnval>(.*)</returnval>", string:buf);
if(!isnull(r[1]))
  set_kb_item(name:"vmware/vcenter/http/" + port + "/concluded", value:r[1]);

set_kb_item(name:"vmware/vcenter/detected", value:TRUE);
set_kb_item(name:"vmware/vcenter/http/detected", value:TRUE);
set_kb_item(name:"vmware/vcenter/http/port", value:port);
set_kb_item(name:"vmware/vcenter/http/" + port + "/version", value:version);
set_kb_item(name:"vmware/vcenter/http/" + port + "/build", value:build);

# mandatory key for gb_apache_struts_CVE_2017_5638.nasl
set_kb_item(name:"www/action_jsp_do", value:TRUE);

exit(0);
