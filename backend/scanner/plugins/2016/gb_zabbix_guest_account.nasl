###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_zabbix_guest_account.nasl 11493 2018-09-20 09:02:35Z asteins $
#
# Zabbix Default Guest Account
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

CPE = "cpe:/a:zabbix:zabbix";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106180");
  script_version("$Revision: 11493 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-20 11:02:35 +0200 (Thu, 20 Sep 2018) $");
  script_tag(name:"creation_date", value:"2016-08-17 11:04:27 +0700 (Wed, 17 Aug 2016)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"Mitigation");

  script_name("Zabbix Default Guest Account");

  script_category(ACT_ATTACK);

  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Default Accounts");
  script_dependencies("zabbix_web_detect.nasl");
  script_mandatory_keys("Zabbix/Web/installed");

  script_tag(name:"summary", value:"Zabbix has a default guest account with no password set. It was possible
to access the dashboard without special authentication.");

  script_tag(name:"vuldetect", value:"Tries to access the dashboard without credentials.");

  script_tag(name:"insight", value:"Initially Zabbix has a guest account with no password set but as well
with no privileges on Zabbix objects which is used to access the user interface when no credentials are set.");

  script_tag(name:"impact", value:"An attacker may use this account to use further attacks to elevate
his privileges.");

  script_tag(name:"solution", value:"Disable the guest account.");


  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!location = get_app_location(cpe: CPE, port: port))
  exit(0);

if (location == "/")
  location = "";

if (http_vuln_check(port: port, url: location + "/zabbix.php?action=dashboard.view", check_header: TRUE,
                    pattern: "<title>Dashboard</title>", extra_check: 'title="Sign out"')) {
  report = report_vuln_url(port: port, url: location + "/zabbix.php?action=dashboard.view");
  security_message(port: port, data: report);
  exit(0);
}

if (http_vuln_check(port: port, url: location + "/dashboard.php", check_header: TRUE,
                    pattern: "<title>.*Dashboard</title>", extra_check: "Connected as 'guest'")) {
  report = report_vuln_url(port: port, url: location + "/dashboard.php");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
