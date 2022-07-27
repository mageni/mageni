##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_emc_data_domain_priv_esc_vuln.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# EMC Data Domain Privilege Escalation Vulnerability
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

CPE = "cpe:/a:emc:data_domain_os";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106806");
  script_version("$Revision: 12106 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-05-16 16:28:36 +0700 (Tue, 16 May 2017)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2017-4983");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("EMC Data Domain Privilege Escalation Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_emc_data_domain_version.nasl");
  script_mandatory_keys("emc/data_domain/version");

  script_tag(name:"summary", value:"EMC Data Domain  OS is affected by a privilege escalation vulnerability
that may potentially be exploited by attackers to compromise the affected system.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"EMC Data Domain OS is potentially vulnerable to a privilege escalation
vulnerability. A rogue administrator may be able to log in as the Security Office (SO) and escalate privileges
by using SO user's public key that is stored unprotected on the Data Domain system.");

  script_tag(name:"affected", value:"EMC Data Domain OS 5.2.x, 5.4.x, 5.5.x, 5.6.x, 5.7.x and 6.0.x.");

  script_tag(name:"solution", value:"Update to 5.7.3.0, 6.0.1.0 or later versions.");

  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2017/May/att-12/ESA-2017-036.txt");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_is_less(version: version, test_version: "5.7.3.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.7.3.0");
  security_message(port: 0, data: report);
  exit(0);
}

if (version =~ "^6\.0\.0") {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.0.1.0");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
