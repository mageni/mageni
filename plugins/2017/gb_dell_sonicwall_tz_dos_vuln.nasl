###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dell_sonicwall_tz_dos_vuln.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# Dell SonicWALL TZ 100 DoS Vulnerability
#
# Authors:
# INCIBE <ics-team@incibe.es>
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

CPE = 'cpe:/a:dell:sonicwall_totalsecure_tz_100_firmware';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106570");
  script_version("$Revision: 12106 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-02-06 14:03:54 +0700 (Mon, 06 Feb 2017)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Dell SonicWALL TZ 100 DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_dell_sonicwall_tz_snmp_detect.nasl");
  script_mandatory_keys("sonicwall/tz/detected");

  script_tag(name:"summary", value:"Dell SonicWALL TZ 100 is prone to a denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Dell SonicWall TotalSecure TZ 100 devices allow remote attackers to cause a
denial of service via a crafted packet.");

  script_tag(name:"affected", value:"Dell SonicWALL TZ 100 devices with firmware before 5.9.1.0-22o.");

  script_tag(name:"solution", value:"Update to firmware version 5.9.1.0-22o or later.");

  script_xref(name:"URL", value:"https://jvn.jp/en/jp/JVN90135579/index.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE))
  exit(0);

check_vers = ereg_replace(string: version, pattern: "-", replace: ".");

if (version_is_less(version: check_vers, test_version: "5.9.1.0.22o")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.9.1.0-22o");
  security_message(port: 0, data: report);
  exit(0);
}

exit(0);
