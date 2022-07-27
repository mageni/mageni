###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hp_power_manager_bof_vuln.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# HP Power Manager Login Form Buffer Overflow Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:hp:power_manager";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801569");
  script_version("$Revision: 11997 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-01-18 07:48:41 +0100 (Tue, 18 Jan 2011)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2010-4113");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("HP Power Manager Login Form Buffer Overflow Vulnerability");

  script_tag(name:"qod_type", value:"remote_banner");

  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("hp_power_manager_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("hp_power_manager/detected");

  script_tag(name:"impact", value:"Successful exploitation could allow users to cause a Denial of Service
condition.");

  script_tag(name:"affected", value:"HP Power Manager (HPPM) before 4.3.2");

  script_tag(name:"insight", value:"The flaw is due to a boundary error when processing URL parameters passed to
the login form of the management web server. It can be exploited to cause a stack-based buffer overflow via a
specially crafted 'Login' variable.");

  script_tag(name:"solution", value:"Upgrade to HP Power Manager (HPPM) 4.3.2 or later.");

  script_tag(name:"summary", value:"The host is running HP Power Manager and is prone to buffer overflow
vulnerability.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/42644");
  script_xref(name:"URL", value:"http://marc.info/?l=bugtraq&m=129251322532373&w=2");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-10-292/");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2010/Dec/1024902.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "4.3.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.3.2");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
