###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_portainer_no_auth_vuln.nasl 10803 2018-08-07 09:41:14Z tpassfeld $
#
# Portainer UI No Authentication Vulnerability
#
# Authors:
# Thorsten Passfeld <thorsten.passfeld@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.114017");
  script_version("$Revision: 10803 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-07 11:41:14 +0200 (Tue, 07 Aug 2018) $");
  script_tag(name:"creation_date", value:"2018-08-06 13:40:12 +0200 (Mon, 06 Aug 2018)");
  script_tag(name:"cvss_base", value:"9.7");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:P");
  script_name("Portainer UI No Authentication Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("global_settings.nasl", "gb_portainer_detect.nasl");
  script_exclude_keys("keys/islocalhost", "keys/islocalnet", "keys/is_private_addr");
  script_mandatory_keys("Portainer/installed");

  script_xref(name:"URL", value:"https://info.lacework.com/hubfs/Containers%20At-Risk_%20A%20Review%20of%2021%2C000%20Cloud%20Environments.pdf");

  script_tag(name:"summary", value:"The script checks if the Portainer Dashboard UI has no authentication enabled
  at the remote web server.");

  script_tag(name:"insight", value:"The installation of Portainer might be misconfigured and therefore
  it is unprotected and exposed to the public.");

  script_tag(name:"vuldetect", value:"Check if authentication is enabled or not.");

  script_tag(name:"impact", value:"Access to the dashboard gives you top level
  access to all aspects of administration for the cluster it is assigned to manage.
  That includes managing applications, containers, starting workloads, adding and
  modifying applications, and setting key security controls.");

  script_tag(name:"solution", value:"It is highly recommended to enable authentication and create an administrator user to avoid exposing your dashboard
  with administrator privileges to the public. Always choose a secure password, especially if your dashboard is exposed to the public.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("network_func.inc");
include("host_details.inc");

CPE = "cpe:/a:portainer:portainer";

if(islocalnet() || islocalhost() || is_private_addr()) exit(0);

if(!port = get_app_port(cpe: CPE)) exit(0);

res = http_get_cache(port: port, item: "/api/status");
if(egrep(pattern: '\\"Authentication\\":false', string: res)) {
  report = "Authentication in Portainer Dashboard UI is disabled!";
  get_app_location(cpe: CPE, port: port, nofork: TRUE);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
