###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_kmccontrols_bac_mult_vuln.nasl 12387 2018-11-16 14:06:23Z cfischer $
#
# KMC Controls BAC-5051E Multiple Vulnerabilities
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
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

CPE = "cpe:/h:kmc_controls:bac-5051e";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106129");
  script_version("$Revision: 12387 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 15:06:23 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-07-12 14:08:41 +0700 (Tue, 12 Jul 2016)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2016-4494", "CVE-2016-4495");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("KMC Controls BAC-5051E Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_kmccontrols_bac_devices_detect.nasl");
  script_mandatory_keys("kmc_controls_bac/detected");

  script_tag(name:"summary", value:"KMC Controls BAC-5051E is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"KMC Controls BAC-5051E is prone to multiple vulnerabilities:

  An unauthorized user can use a CSRF attack to read configuration data from a file. (CVE-2016-4494)

  A missing authorization check allows an unauthorized user to read configuration data from a file. (CVE-2016-4495)");

  script_tag(name:"impact", value:"An unauthorized user can exploit these vulnerabilities to read the
  configuration of the target device.");

  script_tag(name:"affected", value:"Firmware versions prior to E0.2.0.2");

  script_tag(name:"solution", value:"Upgrade to firmware version E0.2.0.2 or later");

  script_xref(name:"URL", value:"https://ics-cert.us-cert.gov/advisories/ICSA-16-126-01");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "0.2.0.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "0.2.0.2");
  security_message(port: 0, data: report);
  exit(0);
}

exit(0);