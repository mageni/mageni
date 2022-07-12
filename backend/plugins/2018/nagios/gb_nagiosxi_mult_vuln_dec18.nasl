##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_nagiosxi_mult_vuln_dec18.nasl 13012 2019-01-10 08:11:33Z asteins $
#
# Nagios XI < 5.5.8 Multiple Vulnerabilities
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

CPE = "cpe:/a:nagios:nagiosxi";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141794");
  script_version("$Revision: 13012 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-10 09:11:33 +0100 (Thu, 10 Jan 2019) $");
  script_tag(name:"creation_date", value:"2018-12-18 09:52:07 +0700 (Tue, 18 Dec 2018)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2018-20171", "CVE-2018-20172");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Nagios XI < 5.5.8 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_nagios_XI_detect.nasl");
  script_mandatory_keys("nagiosxi/installed");

  script_tag(name:"summary", value:"Nagios XI is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Nagios XI is prone to multiple vulnerabilities:

  - XSS Vulnerabilities (CVE-2018-20171, CVE-2018-20172)");

  script_tag(name:"affected", value:"Nagios XI version 5.5.7 and prior.");

  script_tag(name:"solution", value:"Update to version 5.5.8 or later.");

  script_xref(name:"URL", value:"https://www.nagios.com/downloads/nagios-xi/change-log/");
  script_xref(name:"URL", value:"https://www.seebug.org/vuldb/ssvid-97713");
  script_xref(name:"URL", value:"https://www.seebug.org/vuldb/ssvid-97714");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "5.5.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.5.8");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
