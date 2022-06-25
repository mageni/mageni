###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_barracuda_load_balancer_rce_vuln.nasl 12096 2018-10-25 12:26:02Z asteins $
#
# Barracuda Load Balancer Remote Command Execution Vulnerability
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

CPE = 'cpe:/a:barracuda:load_balancer';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106152");
  script_version("$Revision: 12096 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-25 14:26:02 +0200 (Thu, 25 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-07-25 13:42:49 +0700 (Mon, 25 Jul 2016)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Barracuda Load Balancer Remote Command Execution Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_barracuda_load_balancer_detect.nasl");
  script_mandatory_keys("barracuda_lb/installed");

  script_tag(name:"summary", value:"Barracuda Load Balancer is prone to a remote code exectuion
vulnerability.");


  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"By sending a specially crafted request an authenticated attacker may
inject system commands while escalating to root do to relaxed sudo configurations on the appliances.");

  script_tag(name:"impact", value:"An authenticated attacker may execute arbitrary system commands.");

  script_tag(name:"affected", value:"Version <= 5.4.0.004");

  script_tag(name:"solution", value:"Upgrade to Version 6.0.0.004 or later");

  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/138020/Barracuda-Web-App-Firewall-Load-Balancer-Remote-Root.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less_equal(version: version, test_version: "5.4.0.004")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.0.0.004");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
