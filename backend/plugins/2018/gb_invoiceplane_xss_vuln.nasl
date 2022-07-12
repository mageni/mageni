##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_invoiceplane_xss_vuln.nasl 9268 2018-03-29 14:05:16Z cfischer $
#
# InvoicePlane < 1.5.5 XSS Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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

CPE = "cpe:/a:invoiceplane:invoiceplane";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140858");
  script_version("$Revision: 9268 $");
  script_tag(name: "last_modification", value: "$Date: 2018-03-29 16:05:16 +0200 (Thu, 29 Mar 2018) $");
  script_tag(name: "creation_date", value: "2018-03-06 10:57:13 +0700 (Tue, 06 Mar 2018)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2017-18217");

  script_tag(name: "qod_type", value: "remote_banner");

  script_tag(name: "solution_type", value: "VendorFix");

  script_name("InvoicePlane < 1.5.5 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_invoiceplane_detect.nasl");
  script_mandatory_keys("invoiceplane/installed");

  script_tag(name: "summary", value: "An issue was discovered in InvoicePlane. It was observed that the Email
address and Web address parameters are vulnerable to Cross Site Scripting, related to
application/modules/clients/views/view.php, application/modules/invoices/views/view.php, and
application/modules/quotes/views/view.php.");

  script_tag(name: "vuldetect", value: "Checks the version.");

  script_tag(name: "affected", value: "InvoicePlane prior to version 1.5.5.");

  script_tag(name: "solution", value: "Update to version 1.5.5 or later.");

  script_xref(name: "URL", value: "https://github.com/InvoicePlane/InvoicePlane/pull/542");
  script_xref(name: "URL", value: "https://github.com/InvoicePlane/InvoicePlane/pull/551");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "1.5.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.5.5");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
