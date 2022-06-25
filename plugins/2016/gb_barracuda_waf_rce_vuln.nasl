###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_barracuda_waf_rce_vuln.nasl 12313 2018-11-12 08:53:51Z asteins $
#
# Barracuda Web Application Firewall Remote Command Execution Vulnerability
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

CPE = 'cpe:/a:barracuda:web_application_firewall';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106150");
  script_version("$Revision: 12313 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-12 09:53:51 +0100 (Mon, 12 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-07-25 12:59:46 +0700 (Mon, 25 Jul 2016)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Barracuda Web Application Firewall Remote Command Execution Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("barracuda_web_application_firewall_detect.nasl");
  script_mandatory_keys("barracuda_waf/installed");

  script_tag(name:"summary", value:"Barracuda Web Application Firewall is prone to a remote code exectuion
vulnerability.");


  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"By sending a specially crafted request an authenticated attacker may
inject system commands while escalating to root do to relaxed sudo configurations on the appliances.");

  script_tag(name:"impact", value:"An authenticated attacker may execute arbitrary system commands.");

  script_tag(name:"affected", value:"Version <= 8.0.1.007");

  script_tag(name:"solution", value:"Upgrade to Version 8.0.1.008 or later");

  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/138020/Barracuda-Web-App-Firewall-Load-Balancer-Remote-Root.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less_equal(version: version, test_version: "8.0.1.007")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.0.1.008");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
