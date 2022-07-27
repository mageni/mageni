###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_moxa_edr_g903_mult_vuln.nasl 12051 2018-10-24 09:14:54Z asteins $
#
# Moxa EDR G903 Router Multiple Vulnerabilities
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

CPE = "cpe:/h:moxa:edr-g903";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808220");
  script_version("$Revision: 12051 $");
  script_cve_id("CVE-2016-0875", "CVE-2016-0876", "CVE-2016-0877", "CVE-2016-0878",
                "CVE-2016-0879");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-24 11:14:54 +0200 (Wed, 24 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-06-09 13:45:38 +0530 (Thu, 09 Jun 2016)");
  script_tag(name:"qod_type", value:"remote_analysis");
  script_name("Moxa EDR G903 Router Multiple Vulnerabilities");

  script_tag(name:"summary", value:"This host is installed with Moxa EDR G903
  Router and is prone to multiple vulnerabilities");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP GET and
  check whether it is able to access sensitive data.");

  script_tag(name:"insight", value:"The multiple flaws are due to,

  - The copies of configuration and log files are not deleted after completing
    the import function.

  - The configuration and log files can be accessed without authentication.

  - An improper validation of 'ping' function.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  remote attackers to obtain sensitive information by accessing sensitive files
  and also to cause a denial of service (memory consumption).");

  script_tag(name:"affected", value:"Moxa EDR-G903 Versions V3.4.11 and older.");

  script_tag(name:"solution", value:"Upgrade to firmware version v3.4.12 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://ics-cert.us-cert.gov/advisories/ICSA-16-042-01");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_moxa_edr_g903_remote_detect.nasl");
  script_mandatory_keys("Moxa/EDR/G903/Installed");
  script_require_ports("Services/www", 80);
  script_xref(name:"URL", value:"http://www.moxa.com");
  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if(!edrPort = get_app_port(cpe: CPE)){
  exit(0);
}

## Create vulnerable url
url = "/xml/net_led_xml";

if(http_vuln_check(port:edrPort, url:url, check_header:TRUE,
                   pattern:"<eth[0-9]>[0-9.]+</eth[0-9]>",
                   extra_check:"<thermal>"))
{
  report = report_vuln_url(port:edrPort, url:url);
  security_message(port:edrPort, data:report);
  exit(0);
}
exit(0);
