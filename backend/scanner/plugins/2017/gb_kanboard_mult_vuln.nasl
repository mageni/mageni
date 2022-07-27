##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_kanboard_mult_vuln.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# Kanboard Multiple Vulnerabilities
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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

CPE = 'cpe:/a:kanboard:kanboard';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140302");
  script_version("$Revision: 12106 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-08-16 08:40:15 +0700 (Wed, 16 Aug 2017)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");

  script_cve_id("CVE-2017-12850", "CVE-2017-12851");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Kanboard Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("sw_kanboard_detect.nasl");
  script_mandatory_keys("kanboard/installed");

  script_tag(name:"summary", value:"Kanboard is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Kanboard is prone to multiple vulnerabilities:

  - An authenticated standard user could reset the password of other users (including the admin) by altering form
data. (CVE-2017-12850)

  - An authenticated standard user could reset the password of the admin by altering form data. (CVE-2017-12851)");

  script_tag(name:"affected", value:"Kanboard version 1.0.45 and prior.");

  script_tag(name:"solution", value:"Update to version 1.0.46 or later.");

  script_xref(name:"URL", value:"http://seclists.org/oss-sec/2017/q3/297");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "1.0.46")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.0.46");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
