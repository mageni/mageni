###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_http_server_whitespace_mult_vuln.nasl 11983 2018-10-19 10:04:45Z mmartin $
#
# Apache HTTP Server 'Whitespace Defects' Multiple Vulnerabilities
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:apache:http_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812033");
  script_version("$Revision: 11983 $");
  script_cve_id("CVE-2016-8743");
  script_bugtraq_id(95077);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 12:04:45 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-10-16 18:12:40 +0530 (Mon, 16 Oct 2017)");
  ##qod is remote_banner_unreliable as Apache is vulnerable only
  ##when httpd is participating in any chain of proxies or interacting with back-end
  ##application servers, either through mod_proxy or using conventional CGI mechanisms.
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("Apache HTTP Server 'Whitespace Defects' Multiple Vulnerabilities");

  script_tag(name:"summary", value:"This host is running Apache HTTP Server
  and is prone multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaw exists as application accepted a
  broad pattern of unusual whitespace patterns from the user-agent, including
  bare CR, FF, VTAB in parsing the request line and request header lines, as
  well as HTAB in parsing the request line. Any bare CR present in request
  lines was treated as whitespace and remained in the request field member
  'the_request', while a bare CR in the request header field name would be
  honored as whitespace, and a bare CR in the request header field value was
  retained the input headers array. Implied additional whitespace was accepted
  in the request line and prior to the ':' delimiter of any request header lines.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to conduct request smuggling, response splitting and cache pollution
  attacks.");

  script_tag(name:"affected", value:"Apache HTTP Server 2.2.x before 2.2.32 and
  2.3.x through 2.4.24 prior to 2.4.25");

  script_tag(name:"solution", value:"Upgrade to Apache HTTP Server 2.2.32 or 2.4.25
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://httpd.apache.org/security/vulnerabilities_22.html");
  script_xref(name:"URL", value:"https://httpd.apache.org/security/vulnerabilities_24.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("secpod_apache_detect.nasl");
  script_mandatory_keys("apache/installed");
  script_require_ports("Services/www", 80);
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!httpd_port = get_app_port(cpe:CPE)){
  exit(0);
}

if(!httpd_ver = get_app_version(cpe:CPE, port:httpd_port)){
  exit(0);
}


if(httpd_ver =~ "^2\.(3|4)")
{
  if(version_is_less(version:httpd_ver, test_version:"2.4.25")){
    fix = "2.4.25";
  }
}
else if(httpd_ver =~ "^2\.2")
{
  if(version_is_less(version:httpd_ver, test_version:"2.2.32")){
    fix = "2.2.32";
  }
}

if(fix)
{
  report = report_fixed_ver(installed_version:httpd_ver, fixed_version:fix);
  security_message(data:report, port:httpd_port);
  exit(0);
}
exit(0);
