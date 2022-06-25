###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_atutor_mult_xss_vuln.nasl 13462 2019-02-05 09:37:54Z ckuersteiner $
#
# Atutor Multiple Cross Site Scripting Vulnerabilities
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:atutor:atutor";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802561");
  script_version("$Revision: 13462 $");
  script_bugtraq_id(51423);
  script_cve_id("CVE-2012-6528");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2019-02-05 10:37:54 +0100 (Tue, 05 Feb 2019) $");
  script_tag(name:"creation_date", value:"2012-01-17 12:09:44 +0530 (Tue, 17 Jan 2012)");

  script_name("Atutor Multiple Cross Site Scripting Vulnerabilities");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51423/info");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/521260");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/108706/SSCHADV2012-002.txt");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary web
  script or HTML in a user's browser session in the context of an affected site.");

  script_tag(name:"affected", value:"ATutor version 2.0.3");

  script_tag(name:"insight", value:"Multiple flaws are due to an input passed to the various pages are not
  properly sanitised before being returned to the user.");

  script_tag(name:"solution", value:"Update to ATutor Version 2.1");

  script_tag(name:"summary", value:"This host is running Atutor and is prone to multiple cross site
  scripting vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_analysis");

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

url = dir + "/login.php/index.php<script>alert(document.cookie)</script>/index.php";

if (http_vuln_check(port: port, url: url, pattern: "<script>alert\(document.cookie\)</script>",
                    check_header: TRUE)) {
  report = report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
