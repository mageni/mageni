##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_unitrends_mult_vuln.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# Unitrends Multiple Vulnerabilities
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

CPE = 'cpe:/a:unitrends:enterprise_backup';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140447");
  script_version("$Revision: 12106 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-10-23 15:52:55 +0700 (Mon, 23 Oct 2017)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2017-12477", "CVE-2017-12478", "CVE-2017-12479");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Unitrends Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_unitrends_detect.nasl");
  script_mandatory_keys("unitrends/detected");

  script_tag(name:"summary", value:"Unitrends UEB is prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"Unitrends UEB is prone to multiple vulnerabilities:

  - Unauthenticated root RCE (CVE-2017-12477, CVE-2017-12478)

  - Authenticated lowpriv RCE (CVE-2017-12479)");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Unitrends UEB prior to version 10.0.0");

  script_tag(name:"solution", value:"Update to version 10.0.0 or later.");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/42957/");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/42958/");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/42959/");
  script_xref(name:"URL", value:"https://support.unitrends.com/UnitrendsBackup/s/article/000005755");
  script_xref(name:"URL", value:"https://support.unitrends.com/UnitrendsBackup/s/article/000005756");
  script_xref(name:"URL", value:"https://support.unitrends.com/UnitrendsBackup/s/article/000005757");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE))
  exit(0);

if (version_is_less(version: version, test_version: "10.0.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.0.0");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
