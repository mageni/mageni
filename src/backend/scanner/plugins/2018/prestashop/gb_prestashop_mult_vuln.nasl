###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_prestashop_mult_vuln.nasl 13236 2019-01-23 10:23:07Z asteins $
#
# PrestaShop <= 1.7.2.4 Multiple Vulnerabilities
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

CPE = 'cpe:/a:prestashop:prestashop';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140722");
  script_version("$Revision: 13236 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-23 11:23:07 +0100 (Wed, 23 Jan 2019) $");
  script_tag(name:"creation_date", value:"2018-01-23 17:03:37 +0700 (Tue, 23 Jan 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2018-5681", "CVE-2018-5682");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("PrestaShop <= 1.7.2.4 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_prestashop_detect.nasl");
  script_mandatory_keys("prestashop/installed");

  script_tag(name:"summary", value:"PrestaShop is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"PrestaShop is prone to multiple vulnerabilities:

  - XSS via source-code editing on the 'Pages > Edit page' screen. (CVE-2018-5681)

  - User enumeration via the Reset Password feature. (CVE-2018-5682)");

  script_tag(name:"affected", value:"PrestaShop version 1.7.2.4 and prior.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since
  the disclosure of this vulnerability. Likely none will be provided anymore. General solution options
  are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_xref(name:"URL", value:"http://forge.prestashop.com/browse/BOOM-4612");
  script_xref(name:"URL", value:"http://forge.prestashop.com/browse/BOOM-4613");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less_equal(version: version, test_version: "1.7.2.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "None");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
