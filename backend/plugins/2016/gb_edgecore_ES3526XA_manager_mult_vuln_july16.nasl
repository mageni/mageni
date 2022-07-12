###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_edgecore_ES3526XA_manager_mult_vuln_july16.nasl 12455 2018-11-21 09:17:27Z cfischer $
#
# EdgeCore ES3526XA Manager Multiple Vulnerabilities
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/o:edgecore:es3526xa_manager";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808238");
  script_version("$Revision: 12455 $");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-11-21 10:17:27 +0100 (Wed, 21 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-06-27 15:50:17 +0530 (Mon, 27 Jun 2016)");
  script_tag(name:"qod_type", value:"remote_vul");
  script_name("EdgeCore ES3526XA Manager Multiple Vulnerabilities");

  script_tag(name:"summary", value:"This host is installed with EdgeCore
  ES3526XA Manager and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP GET and
  check whether it is able to bypass authentication or not.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - No CSRF Token is generated per page and / or per (sensitive) function.

  - An improper access control mechanism so that any functions can be performed
    by directly calling the function URL (GET/POST) without any authentication.

  - It is possible to login with default credential admin:admin or guest:guest,
    and mandatory password change is not enforced by the application.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers silent execution of unauthorized actions on the device such as
  password change, configuration parameter changes, to bypass authentication
  and to perform any administrative functions such as add, update, delete users.");

  script_tag(name:"affected", value:"EdgeCore - Layer2+ Fast Ethernet Standalone Switch ES3526XA Manager.
  For the affected switch information refer the reference link.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2016/Jun/62");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_edgecore_ES3526XA_manager_remote_detect.nasl");
  script_mandatory_keys("EdgeCore/ES3526XA/Manager/Installed");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("http_func.inc");
include("misc_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if(!edgePort = get_app_port(cpe:CPE)) exit(0);

## Create hard-coded account list
## Default credentials
credentials = make_list("admin:admin", "guest:guest");

foreach credential (credentials)
{
  userpass = base64(str:credential);

  buf = http_get_cache(item:"/", port:edgePort);

  if("401 Unauthorized" >!< buf) exit(0);

  req = 'GET / HTTP/1.1\r\n' +
        'Authorization: Basic ' + userpass + '\r\n' +
        '\r\n';
  buf = http_keepalive_send_recv(port:edgePort, data:req, bodyonly:FALSE);

  ## No other confirmation is possible
  if(buf =~ "HTTP/1.. 200 OK" && "cluster_info" >< buf &&
     "cluster_main.htm" >< buf && "cluster_link.htm" >< buf)
  {
    report = 'It was possible to login using the following credentials:\n\n' + credential;
    security_message(port:edgePort, data:report);
    exit(0);
  }
}
