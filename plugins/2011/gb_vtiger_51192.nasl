###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vtiger_51192.nasl 12926 2019-01-03 03:38:48Z ckuersteiner $
#
# vtiger CRM 'graph.php ' Script Authentication Bypass Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
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

CPE = "cpe:/a:vtiger:vtiger_crm";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103374");
  script_bugtraq_id(51192);
  script_version("$Revision: 12926 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("vtiger CRM 'graph.php ' Script Authentication Bypass Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51192");
  script_xref(name:"URL", value:"http://www.vtiger.com/");
  script_xref(name:"URL", value:"http://francoisharvey.ca/2011/12/advisory-meds-2011-01-vtigercrm-anonymous-access-to-setting-module/");

  script_tag(name:"last_modification", value:"$Date: 2019-01-03 04:38:48 +0100 (Thu, 03 Jan 2019) $");
  script_tag(name:"creation_date", value:"2011-12-29 10:36:49 +0100 (Thu, 29 Dec 2011)");
  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("gb_vtiger_crm_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("vtiger/detected");

  script_tag(name:"solution", value:"Vendor updates are available. Please see the references for details.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"vtiger CRM is prone to an authentication-bypass vulnerability.

An attacker can exploit this issue to bypass the authentication
process, download the database backup and modify configurations settings.

vtiger CRM 5.2.1 is vulnerable. Other versions may also be affected.");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe:CPE))
  exit(0);

if (!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if (dir == "/")
  dir = "";

url = dir + "/graph.php?module=Settings&action=OrganizationConfig&parenttab=Settings";

if (http_vuln_check(port: port, url: url, pattern: "Company Details",
                    extra_check: make_list("EditCompanyDetails", "Company Name"))) {
  report = report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
