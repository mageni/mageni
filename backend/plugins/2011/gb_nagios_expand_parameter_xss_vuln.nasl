###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_nagios_expand_parameter_xss_vuln.nasl 12962 2019-01-08 07:46:53Z ckuersteiner $
#
# Nagios 'expand' Parameter Cross-Site Scripting Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
###############################################################################

CPE = "cpe:/a:nagios:nagios";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801894");
  script_version("$Revision: 12962 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-08 08:46:53 +0100 (Tue, 08 Jan 2019) $");
  script_tag(name:"creation_date", value:"2011-06-07 13:29:28 +0200 (Tue, 07 Jun 2011)");
  script_cve_id("CVE-2011-2179");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_name("Nagios 'expand' Parameter Cross-Site Scripting Vulnerability");

  script_xref(name:"URL", value:"http://tracker.nagios.org/view.php?id=224");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/518221");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2011/Jun/22");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/101899/SSCHADV2011-006.txt");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("nagios_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("nagios/installed");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary
HTML and script code in a user's browser session in the context of an affected site.");

  script_tag(name:"affected", value:"Nagios versions 3.2.3 and prior.");

  script_tag(name:"insight", value:"The flaw is caused by improper validation of user-supplied input
passed via the 'expand' parameter in cgi-bin/config.cgi, which allows attackers
to execute arbitrary HTML and script code on the web server.");

  script_tag(name:"solution", value:"Upgrade to Nagios version 3.3.1 or later.");

  script_tag(name:"summary", value:"This host is running Nagios and is prone to cross site scripting
vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.nagios.org/");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if (!port = get_app_port(cpe:CPE))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

url = dir + "/cgi-bin/config.cgi?type=command&expand=<script>" +
            "alert(String.fromCharCode(88,83,83))</script>";

if (http_vuln_check(port:port, url:url, check_header: TRUE,
                    pattern:"><script>alert\(String.fromCharCode\(88,83,83\)\)</script>")) {
  report = report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
