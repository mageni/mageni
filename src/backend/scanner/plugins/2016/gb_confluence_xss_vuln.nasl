###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_confluence_xss_vuln.nasl 12096 2018-10-25 12:26:02Z asteins $
#
# Atlassian Confluence XSS and Insecure Direct Object Reference Vulnerabilities
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
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

CPE = "cpe:/a:atlassian:confluence";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806815");
  script_version("$Revision: 12096 $");
  script_cve_id("CVE-2015-8398", "CVE-2015-8399");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-25 14:26:02 +0200 (Thu, 25 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-01-08 16:21:20 +0530 (Fri, 08 Jan 2016)");
  script_tag(name:"qod_type", value:"remote_vul");
  script_name("Atlassian Confluence XSS and Insecure Direct Object Reference Vulnerabilities");

  script_tag(name:"summary", value:"This host is installed with Atlassian
  Confluence and is prone to cross site scripting and insecure direct object
  reference vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP GET and
  check whether it is able to read cookie or not.");

  script_tag(name:"insight", value:"Multiple flaws are due to

  - An improper sanitization of user supplied input via different parameters
    in the REST API.

  - An Insecure Direct Object Reference via parameter 'decoratorName'.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary script code in a user's browser session
  and to read configuration files from the application.");

  script_tag(name:"affected", value:"Confluence versions 5.9.1, 5.8.14
  5.8.15, 5.2");

  script_tag(name:"solution", value:"Upgrade to Confluence version 5.8.17 or later");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/39170/");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2016/Jan/5");
  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/135130/confluence-xssdisclose.txt");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_atlassian_confluence_detect.nasl");
  script_mandatory_keys("atlassian_confluence/installed");
  script_require_ports("Services/www", 80);
  script_xref(name:"URL", value:"https://www.atlassian.com/software/confluence");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!http_port = get_app_port(cpe:CPE)){
  exit(0);
}

if(!dir = get_app_location(cpe:CPE, port:http_port)){
  exit(0);
}

url = dir + '/rest/prototype/1/session/check/something%3Cimg%20src%3da%20onerror%3dalert%28document.cookie%29%3E';

if(http_vuln_check(port:http_port, url:url,  pattern:"alert\(document.cookie\)", check_header:TRUE,
                  extra_check:"Expected user"))
{
  report = report_vuln_url( port:http_port, url:url );
  security_message(port:http_port, data:report);
  exit(0);
}
