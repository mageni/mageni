###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_inedo_proget_csrf_vuln.nasl 12544 2018-11-27 08:19:05Z mmartin $
#
# Inedo ProGet < 5.0.4 CSRF Vulnerability
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

CPE = "cpe:/a:inedo:proget";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141541");
  script_version("$Revision: 12544 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-27 09:19:05 +0100 (Tue, 27 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-10-01 16:20:09 +0700 (Mon, 01 Oct 2018)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2017-15608");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Inedo ProGet < 5.0.4 CSRF Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_inedo_proget_detect.nasl");
  script_mandatory_keys("inedo_proget/detected");

  script_tag(name:"summary", value:"Inedo ProGet is prone to a CSRF vulnerability allowing an attacker to change
advanced settings.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"ProGet versions prior to 5.0.4");

  script_tag(name:"solution", value:"Update to version 5.0.4 or later.");

  script_xref(name:"URL", value:"https://inedo.com/blog/proget-50-beta5-released");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "5.0.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.0.4");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
