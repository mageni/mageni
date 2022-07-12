###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vmware_vcenter_detect.nasl 10312 2018-06-25 11:10:27Z cfischer $
#
# VMware ESX Detection (Web)
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.103659");
  script_version("$Revision: 10312 $");
  script_tag(name:"last_modification", value:"$Date: 2018-06-25 13:10:27 +0200 (Mon, 25 Jun 2018) $");
  script_tag(name:"creation_date", value:"2013-02-06 17:30:38 +0100 (Wed, 06 Feb 2013)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("VMware vCenter Detection (Web)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.vmware.com");

  script_tag(name:"summary", value:"This host is running VMware vCenter.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");

port = get_http_port(default:443);
host = http_host_name(port:port);

soc = open_sock_tcp(port);
if(!soc){
  exit(0);
}

req  = string("GET / HTTP/1.1\r\n");
req += string("Host: ", host, "\r\n\r\n");

send(socket:soc, data:req);
buf = recv(socket:soc, length:8192);
close(soc); # needed for the strange behaviour of esx 3.x
if("VMware" >!< buf)exit(0);

soc = open_sock_tcp(port);
if(!soc)exit(0);

vers = "unknown";

req  = string("POST /sdk HTTP/1.1\r\n");
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

if("RetrieveServiceContentResponse" >!< buf)exit(0);
if("<fullName>VMware vCenter Server" >!< buf)exit(0);

version = eregmatch(pattern:"<version>([0-9.]+)</version>", string:buf);
if(!isnull(version[1])) {
  vers = version[1];
}

name = eregmatch(pattern:"<name>(.*)</name>", string:buf);
if(!isnull(name[1])) {
  typ = name[1];
}

if("<build>" >< buf) {
  build = eregmatch(pattern:"<build>([0-9]+)</build>", string:buf);
  if(!isnull(build[1])) {
   build =  build[1];
  }
}

r = eregmatch(pattern:"<returnval>(.*)</returnval>", string:buf);
if(!isnull(r[1])) {
  rs = r[1];
}

cpe = build_cpe(value:vers, exp:"^([0-9.]+)", base:"cpe:/a:vmware:vcenter:");
if(isnull(cpe))
  cpe = 'cpe:/a:vmware:vcenter';

register_product(cpe:cpe, location:port + "/tcp", port:port);

set_kb_item(name:"VMware_vCenter/installed", value:TRUE);
set_kb_item(name:"VMware_vCenter/version", value:vers);
set_kb_item(name:"VMware_vCenter/build", value:build);
set_kb_item(name:"VMware_vCenter/port", value:port);

# mandatory key for gb_apache_struts_CVE_2017_5638.nasl
set_kb_item(name:"www/action_jsp_do", value:TRUE);

log_message(data:build_detection_report(app:"VMware vCenter Server", version:vers, install:port + '/tcp', cpe:cpe, concluded:rs),
            port:port);

exit(0);
