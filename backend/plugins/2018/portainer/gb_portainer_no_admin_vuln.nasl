###############################################################################
# OpenVAS Vulnerability Test
#
# Portainer UI No Administrator Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.114016");
  script_version("2019-05-13T12:10:49+0000");
  script_tag(name:"last_modification", value:"2019-05-13 12:10:49 +0000 (Mon, 13 May 2019)");
  script_tag(name:"creation_date", value:"2018-08-06 11:59:55 +0200 (Mon, 06 Aug 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_name("Portainer UI No Administrator Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_portainer_detect.nasl");
  script_mandatory_keys("portainer/detected");

  script_xref(name:"URL", value:"https://info.lacework.com/hubfs/Containers%20At-Risk_%20A%20Review%20of%2021%2C000%20Cloud%20Environments.pdf");
  script_xref(name:"URL", value:"https://github.com/portainer/portainer/issues/2475");
  script_xref(name:"URL", value:"https://github.com/portainer/portainer/pull/2500");

  script_cve_id("CVE-2018-19367");

  script_tag(name:"summary", value:"Portainer is prone to an information disclosure and authentication bypass vulnerability.");

  script_tag(name:"insight", value:"The configuration of Portainer might be incomplete and therefore
  it is unprotected and potentially exposed to the public. This vulnerability affects all versions until
  version 1.19.2. Versions later than 1.19.2 stop the Portainer instance after 5 minutes if no administrator user was created.");

  script_tag(name:"vuldetect", value:"Checks if the Portainer Dashboard UI has no administrator user yet or if it would be possible to create a new administrator user.");

  script_tag(name:"impact", value:"Access to the dashboard gives you top level
  access to all aspects of administration for the cluster it is assigned to manage.
  That includes managing applications, containers, starting workloads, adding and
  modifying applications, and setting key security controls.");

  script_tag(name:"solution", value:"It is highly recommended to create an administrator user to avoid exposing your dashboard
  with administrator privileges to the public. Update to a version later than 1.19.2 and always choose a secure password,
  especially if your dashboard is exposed to the public.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("network_func.inc");
include("host_details.inc");

CPE = "cpe:/a:portainer:portainer";

if(!port = get_app_port(cpe: CPE)) exit(0);

res = http_get_cache(port: port, item: "/api/users/admin/check");

if("User not found" >< res || "No administrator account found inside the database" >< res || "Object not found inside the database" >< res) {
  report = "Portainer Dashboard UI is missing an administrator user!";
  get_app_location(cpe: CPE, port: port, nofork: TRUE);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
