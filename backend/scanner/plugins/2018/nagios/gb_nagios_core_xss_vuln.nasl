##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_nagios_core_xss_vuln.nasl 13999 2019-03-05 13:15:01Z cfischer $
#
# Nagios Core <= 4.4.2 XSS Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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

CPE = "cpe:/a:nagios:nagios";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141795");
  script_version("$Revision: 13999 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-05 14:15:01 +0100 (Tue, 05 Mar 2019) $");
  script_tag(name:"creation_date", value:"2018-12-18 10:01:00 +0700 (Tue, 18 Dec 2018)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");

  script_cve_id("CVE-2018-18245");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"NoneAvailable");

  script_name("Nagios Core <= 4.4.2 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("nagios_detect.nasl");
  script_mandatory_keys("nagios/installed");

  script_tag(name:"summary", value:"Nagios Core 4.4.2 has XSS via the alert summary reports of plugin results, as
  demonstrated by a SCRIPT element delivered by a modified check_load plugin to NRPE.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Nagios Core version 4.4.2 and probably prior.");

  script_tag(name:"solution", value:"No known solution is available as of 05th March, 2019. Information regarding this
  issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://herolab.usd.de/wp-content/uploads/sites/4/2018/12/usd20180026.txt");
  script_xref(name:"URL", value:"https://www.nagios.org/downloads/nagios-core");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less_equal(version: version, test_version: "4.4.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "None");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);