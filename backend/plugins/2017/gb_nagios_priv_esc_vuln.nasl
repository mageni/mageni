###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_nagios_priv_esc_vuln.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# Nagios Privilege Escalation Vulnerability
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

CPE = 'cpe:/a:nagios:nagios';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106606");
  script_version("$Revision: 12106 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-02-17 10:06:51 +0700 (Fri, 17 Feb 2017)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2016-10089");
  script_bugtraq_id(95171);

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Nagios Privilege Escalation Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("nagios_detect.nasl");
  script_mandatory_keys("nagios/installed");

  script_tag(name:"summary", value:"Nagios is prone to a privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The init script for Nagios calls 'chown' on a path under the control of
Nagios. CVE-2016-8641 describes an attack wherein that restricted user replaces the aforementioned path with a
symlink. An identical attack not addressed by CVE-2016-8641 works with hardlinks.");

  script_tag(name:"impact", value:"A local attacker may gain root privileges.");

  script_tag(name:"affected", value:"Nagios before 4.3.3 (4.x.x).");

  script_tag(name:"solution", value:"Update to Nagios 4.3.3 or a later version.");

  script_xref(name:"URL", value:"http://seclists.org/oss-sec/2016/q4/783");
  script_xref(name:"URL", value:"https://github.com/NagiosEnterprises/nagioscore/blob/nagios-4.3.3/daemon-init.in");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "4.3.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.3.3");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
