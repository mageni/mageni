###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sophos_utm_url_xss_vuln.nasl 12455 2018-11-21 09:17:27Z cfischer $
#
# Sophos UTM URL Reflected Cross Site Scripting Vulnerability
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

CPE = "cpe:/a:sophos:utm";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807519");
  script_version("$Revision: 12455 $");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-11-21 10:17:27 +0100 (Wed, 21 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-03-04 18:36:07 +0530 (Fri, 04 Mar 2016)");
  script_tag(name:"qod_type", value:"remote_active");
  script_name("Sophos UTM URL Reflected Cross Site Scripting Vulnerability");

  script_tag(name:"summary", value:"This host is installed with Sophos UTM
  and is prone to reflected cross site scripting Vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP GET and
  check whether it is able to read cookie or not.");

  script_tag(name:"insight", value:"The flaw is due to an insufficient
  validation of user supplied input via the 'url' of a web site protected by
  Sophos UTM 525.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary script code in a user's browser session, read
  arbitrary files and to trigger specific actions.");

  script_tag(name:"affected", value:"Sophos UTM version 9.352-6 and 94988");

  script_tag(name:"solution", value:"Upgrade to Sophos UTM 9.354 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/537662");
  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/136019/SYSS-2016-009.txt");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_sophos_utm_remote_detect.nasl");
  script_mandatory_keys("Sophos/UTM/Installed");
  script_require_ports("Services/www", 8080);
  script_xref(name:"URL", value:"https://www.sophos.com");
  exit(0);
}


include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if(!http_port = get_app_port(cpe:CPE)){
  exit(0);
}

if(!dir = get_app_location(cpe:CPE, port:http_port)){
  exit(0);
}

url = dir + '/%3Cscript%3Ealert(document.cookie)%3C/script%3E';

if(http_vuln_check(port:http_port, url:url, check_header:TRUE,
   pattern:"<script>alert\(document.cookie\)</script",
   extra_check:"<title>Request blocked</title>"))
{
  report = report_vuln_url( port:http_port, url:url );
  security_message(port:http_port, data:report);
  exit(0);
}
