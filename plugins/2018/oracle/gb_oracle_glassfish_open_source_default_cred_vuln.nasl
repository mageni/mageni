###############################################################################
# OpenVAS Vulnerability Test
#
# Oracle GlassFish Open Source Default Credentials Vulnerability
#
# Authors:
# Rajat Mishra <rajatm@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation;
# either version 2 of the License, or (at your option) any later version.
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

CPE = "cpe:/a:oracle:glassfish_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813576");
  script_version("2019-05-20T07:06:11+0000");
  script_cve_id("CVE-2018-14324");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-20 07:06:11 +0000 (Mon, 20 May 2019)");
  script_tag(name:"creation_date", value:"2018-07-17 12:45:41 +0530 (Tue, 17 Jul 2018)");

  script_name("Oracle GlassFish Open Source Default Credentials Vulnerability");

  script_tag(name:"summary", value:"This host is running Oracle GlassFish Server
  and is prone to a default credentials vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to the demo feature in Oracle
  GlassFish Open Source Edition having TCP port 7676 open by default with a password
  of admin for the admin account.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to obtain potentially sensitive information, perform database operations, or
  manipulate the demo via a JMX RMI session.");

  script_tag(name:"affected", value:"Oracle GlassFish Server versions 5.0.");

  script_tag(name:"solution", value:"No known solution is available as of 20th May, 2019.
  Information regarding this issue will be updated once solution details are available.");

  script_tag(name:"solution_type", value:"NoneAvailable");
  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"https://www.securitytracker.com/id/1041292");
  script_xref(name:"URL", value:"https://github.com/eclipse-ee4j/glassfish/issues/22500");

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("GlassFish_detect.nasl");
  script_mandatory_keys("GlassFish/installed");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!version = get_app_version(cpe:CPE, port:port))
  exit(0);

if(version_is_equal(version:version, test_version:"5.0")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"None");
  security_message(data:report, port:port);
  exit(0);
}

exit(99);