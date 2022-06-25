##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_emc_isilon_onefs_priv_esc_vuln2.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# EMC Isilon OneFS Privilege Escalation Vulnerability
#
# Authors:
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

CPE = "cpe:/o:emc:isilon_onefs";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106889");
  script_version("$Revision: 12106 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-06-21 11:18:56 +0700 (Wed, 21 Jun 2017)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_cve_id("CVE-2017-4988");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("EMC Isilon OneFS Privilege Escalation Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Privilege escalation");
  script_dependencies("gb_emc_isilon_onefs_snmp_detect.nasl", "gb_emc_isilon_onefs_ftp_detect.nasl",
"gb_emc_isilon_onefs_ntp_detect.nasl");
  script_mandatory_keys("emc_isilon_onefs/detected");

  script_tag(name:"summary", value:"EMC Isilon OneFS is affected by a privilege escalation vulnerability that
could potentially be exploited by attackers to compromise the affected system.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A cluster administrator, a compadmin user, or any user who has been given
sudo privileges to run  isi_for_array commands could potentially exploit this vulnerability to gain root-level
access to a cluster.");

  script_tag(name:"affected", value:"EMC Isilon OneFS 7.1.x, 7.2.0 - 7.2.1.4, 8.0.0 - 8.0.0.3, 8.0.1.0");

  script_tag(name:"solution", value:"Update to version 7.2.1.5, 8.0.0.4, 8.0.1.1 or later.");

  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2017/Jun/41");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_is_less(version: version, test_version: "7.1.0.0"))
  exit(99);

if (version_is_less(version: version, test_version: "7.2.1.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.2.1.5");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "8.0.0", test_version2: "8.0.0.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.0.0.4");
  security_message(port: 0, data: report);
  exit(0);
}

if (version == "8.0.1.0") {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.0.1.1");
  security_message(port: 0, data: report);
  exit(0);
}

exit(0);
