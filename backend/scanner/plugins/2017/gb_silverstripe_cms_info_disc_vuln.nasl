###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_silverstripe_cms_info_disc_vuln.nasl 11874 2018-10-12 11:28:04Z mmartin $
#
# SilverStripe CMS Information Disclosure Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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

CPE = "cpe:/a:silverstripe:silverstripe";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106795");
  script_version("$Revision: 11874 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:28:04 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-04-27 14:38:21 +0200 (Thu, 27 Apr 2017)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("SilverStripe CMS Information Disclosure Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_silverstripe_cms_detect.nasl");
  script_mandatory_keys("silverstripe_cms/installed");

  script_tag(name:"summary", value:"SilverStripe CMS is prone to a path disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a HTTP request and checks the response.");

  script_tag(name:"insight", value:"Accessing /dev/build/ may return the installation path which may lead
to further attacks.");

  script_tag(name:"affected", value:"SilverStripe 3.1.9 and prior.");

  script_tag(name:"solution", value:"Update to version 3.1.10 or later.");

  script_xref(name:"URL", value:"https://www.osisecurity.com.au/silverstripe-cms---path-disclosure.html");
  script_xref(name:"URL", value:"https://github.com/silverstripe/silverstripe-framework/pull/3854");

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

url = dir + "/dev/build/";

if (http_vuln_check(port: port, url: url, pattern: "output started on .*/dev/DebugView.php")) {
  report = report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
