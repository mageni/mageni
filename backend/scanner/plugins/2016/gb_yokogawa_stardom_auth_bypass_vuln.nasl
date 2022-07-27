###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_yokogawa_stardom_auth_bypass_vuln.nasl 12096 2018-10-25 12:26:02Z asteins $
#
# Yokogawa STARDOM Authentication Bypass Vulnerability
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

CPE = 'cpe:/a:yokogawa:stardom_fcn-fcj';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106271");
  script_version("$Revision: 12096 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-25 14:26:02 +0200 (Thu, 25 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-09-20 10:41:21 +0700 (Tue, 20 Sep 2016)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2016-4860");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Yokogawa STARDOM Authentication Bypass Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_yokogawa_stardom_detect.nasl");
  script_mandatory_keys("yokogawa_stardom/detected");

  script_tag(name:"summary", value:"Yokogawa STARDOM is prone to a authenticatio bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Logic Designer can connect to STARDOM controller without authentication.");

  script_tag(name:"impact", value:"An attacker may be able to exploit this vulnerability to execute commands
such as stop application program, change values, and modify application.");

  script_tag(name:"affected", value:"STARDOM FCN/FCJ controller (from Version R1.01 to R4.01).");

  script_tag(name:"solution", value:"Update to version R4.02 or later.");

  script_xref(name:"URL", value:"https://web-material3.yokogawa.com/YSAR-16-0002-E.pdf");
  script_xref(name:"URL", value:"https://ics-cert.us-cert.gov/advisories/ICSA-16-259-01");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE))
  exit(0);

if (version_is_less(version: version, test_version: "r4.02")) {
  report = report_fixed_ver(installed_version: toupper(version), fixed_version: "R4.02");
  security_message(port: 0, data: report);
  exit(0);
}

exit(0);
