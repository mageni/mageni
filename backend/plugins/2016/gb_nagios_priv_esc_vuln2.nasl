###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_nagios_priv_esc_vuln2.nasl 12096 2018-10-25 12:26:02Z asteins $
#
# Nagios Privilege Escalation Vulnerability
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

CPE = 'cpe:/a:nagios:nagios';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106475");
  script_version("$Revision: 12096 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-25 14:26:02 +0200 (Thu, 25 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-12-15 10:22:34 +0700 (Thu, 15 Dec 2016)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2016-9566");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Nagios Privilege Escalation Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("nagios_detect.nasl");
  script_mandatory_keys("nagios/installed");

  script_tag(name:"summary", value:"Nagios is prone to a privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The Nagios daemon was found to open the log file before dropping its root
privileges on startup. If an attacker managed to gain access to an account of 'nagios' or any other account
belonging to the 'nagios' group, they would be able to replace the log file with a symlink to an arbitrary file
on the system. This vulnerability could be used by an attacker to escalate their privileges from nagios
user/group to root for example by creating a malicious /etc/ld.so.preload file.");

  script_tag(name:"impact", value:"A local attacker may escalate the privileges.");

  script_tag(name:"affected", value:"Nagios 4.2.2 and before.");

  script_tag(name:"solution", value:"Update to version 4.2.3 or later.");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/40774/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "4.2.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.2.3");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
