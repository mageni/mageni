###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mort_bay_jetty_mult_xss_vuln.nasl 13962 2019-03-01 14:14:42Z cfischer $
#
# Mort Bay Jetty Multiple Cross Site Scripting Vulnerabilities
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:eclipse:jetty";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800285");
  script_version("$Revision: 13962 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-01 15:14:42 +0100 (Fri, 01 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-02-02 07:26:26 +0100 (Tue, 02 Feb 2010)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2009-4612");

  script_name("Mort Bay Jetty Multiple Cross Site Scripting Vulnerabilities");

  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2009/Oct/319");
  script_xref(name:"URL", value:"http://www.ush.it/team/ush/hack_httpd_escape/adv.txt");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("gb_jetty_detect.nasl");
  script_family("Web application abuses");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("Jetty/installed");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to execute arbitrary
HTML and script code in a user's browser session in the context of an affected site allowing Cross-Site Scripting
attacks.");

  script_tag(name:"affected", value:"Jetty version 6.0.x to 6.1.21");

  script_tag(name:"insight", value:"Multiple flaws exists due to error in 'PATH_INFO' parameter, it is not
properly sanitised data before used via the default URI under 'jspsnoop/', 'jspsnoop/ERROR/',
'jspsnoop/IOException/' and 'snoop.jsp'");

  script_tag(name:"summary", value:"This host is running Mort Bay Jetty and is prone to multiple Cross Site
Scripting vulnerabilities.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}


include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if (!jettyPort = get_app_port(cpe:CPE))
  exit(0);

url = "/test/jsp/dump.jsp?<script>alert(document.cookie)</script>";

if (http_vuln_check(port: jettyPort, url: url, pattern: "<script>alert\(document" + ".cookie\)</script>",
                    check_header: TRUE)) {
  report = report_vuln_url(port: jettyPort, url: url);
  security_message(port: jettyPort, data: report);
  exit(0);
}

exit(0);
