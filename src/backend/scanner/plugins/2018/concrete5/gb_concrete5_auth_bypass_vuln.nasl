###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_concrete5_auth_bypass_vuln.nasl 12116 2018-10-26 10:01:35Z mmartin $
#
# Concrete5 Authentication Bypass Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH
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

CPE = "cpe:/a:concrete5:concrete5";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140817");
  script_version("$Revision: 12116 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 12:01:35 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-02-27 13:37:17 +0700 (Tue, 27 Feb 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2017-18195");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Concrete5 Authentication Bypass Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_concrete5_detect.nasl");
  script_mandatory_keys("concrete5/installed");

  script_tag(name:"summary", value:"An issue was discovered in tools/conversations/view_ajax.php in Concrete5.
An unauthenticated user can enumerate comments from all blog posts by POSTing requests to
/index.php/tools/required/conversations/view_ajax with incremental 'cnvID' integers.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Concrete5 prior to version 8.3.0");

  script_tag(name:"solution", value:"Update to version 8.3.0 or later.");

  script_xref(name:"URL", value:"https://github.com/concrete5/concrete5/releases/tag/8.3.0");
  script_xref(name:"URL", value:"https://github.com/r3naissance/NSE/blob/master/http-vuln-cve2017-18195.nse");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "8.3.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.3.0");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
