###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_firestats_41548.nasl 10772 2018-08-04 15:54:37Z cfischer $
#
# FireStats Multiple Cross Site Scripting Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:firestats:firestats";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100710");
  script_version("$Revision: 10772 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-04 17:54:37 +0200 (Sat, 04 Aug 2018) $");
  script_tag(name:"creation_date", value:"2010-07-13 12:45:31 +0200 (Tue, 13 Jul 2010)");
  script_bugtraq_id(41548);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("FireStats Multiple Cross Site Scripting Vulnerabilities");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("firestats_detect.nasl");
  script_mandatory_keys("firestats/installed");

  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/41548");
  script_xref(name:"URL", value:"http://firestats.cc/");
  script_xref(name:"URL", value:"http://firestats.cc/ticket/1358#comment:3");

  script_tag(name:"solution", value:"Updates are available, please see the references for more information.");

  script_tag(name:"summary", value:"FireStats is prone to multiple cross-site scripting vulnerabilities because
  it fails to properly sanitize user-supplied input.");

  script_tag(name:"impact", value:"An attacker may leverage these issues to execute arbitrary script code in
  the browser of an unsuspecting user in the context of the affected site. This may allow the attacker to steal
  cookie-based authentication credentials and to launch other attacks.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

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

url = dir + "/php/window-add-excluded-ip.php?edit=%3Cscript%3Ealert(%27openvas-xss-test%27)%3C/script%3E";

if (http_vuln_check(port: port,url: url,pattern: "<script>alert\('openvas-xss-test'\)</script>",
                    check_header: TRUE)) {
  report = report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
