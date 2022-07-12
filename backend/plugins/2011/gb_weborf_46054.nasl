###############################################################################
# OpenVAS Vulnerability Test
#
# Weborf 'get_param_value()' Function HTTP Header Handling Denial Of Service Vulnerability
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103050");
  script_version("2019-05-13T14:05:09+0000");
  script_tag(name:"last_modification", value:"2019-05-13 14:05:09 +0000 (Mon, 13 May 2019)");
  script_tag(name:"creation_date", value:"2011-01-31 12:59:22 +0100 (Mon, 31 Jan 2011)");
  script_bugtraq_id(46054);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Weborf 'get_param_value()' Function HTTP Header Handling Denial Of Service Vulnerability");

  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/46054");
  script_xref(name:"URL", value:"http://galileo.dmi.unict.it/svn/weborf/trunk/CHANGELOG");
  script_xref(name:"URL", value:"http://galileo.dmi.unict.it/wiki/weborf/doku.php");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Web Servers");
  script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("gb_weborf_webserver_detect.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("weborf/detected");

  script_tag(name:"solution", value:"Updates are available. Please see the references for details.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"Weborf is prone to a denial-of-service vulnerability.");

  script_tag(name:"impact", value:"Remote attackers can exploit this issue to cause the application to
  crash, denying service to legitimate users.");

  script_tag(name:"affected", value:"Versions prior to Weborf 0.12.5 are vulnerable.");

  exit(0);
}

include("http_func.inc");
include("version_func.inc");

port = get_http_port(default:8080);

if(!vers = get_kb_item(string("www/", port, "/Weborf")))exit(0);

if(!isnull(vers) && vers >!< "unknown") {
  if(version_is_less(version: vers, test_version: "0.12.5")) {
    security_message(port:port);
    exit(0);
  }
}

exit(0);