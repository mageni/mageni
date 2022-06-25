###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_atlassian_confluence_mult_vuln.nasl 12338 2018-11-13 14:51:17Z asteins $
#
# Atlassian Confluence Multiple Vulnerabilities
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

CPE = "cpe:/a:atlassian:confluence";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106113");
  script_version("$Revision: 12338 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-13 15:51:17 +0100 (Tue, 13 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-07-04 12:33:39 +0700 (Mon, 04 Jul 2016)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2015-8398", "CVE-2015-8399");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Atlassian Confluence Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_atlassian_confluence_detect.nasl");
  script_mandatory_keys("atlassian_confluence/installed");

  script_tag(name:"summary", value:"Atlassian Confluence is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Atlassian Confluence is prone to two vulnerabilities:

Cross-site scripting (XSS) vulnerability allows remote attackers to inject arbitrary web script or HTML
via the PATH_INFO to rest/prototype/1/session/check. (CVE-2015-8398)

Remote authenticated users may read configuration files via the decoratorName parameter to
spaces/viewdefaultdecorator.action or admin/viewdefaultdecorator.action. (CVE-2015-8399)");

  script_tag(name:"impact", value:"Unauthenticated remote attackers may inject arbitrary scripts.
Authenticated attackers may read configuration files.");

  script_tag(name:"affected", value:"Version 5.8.16 and previous");

  script_tag(name:"solution", value:"Update to 5.8.17 or later versions.");

  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2016/Jan/9");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "5.8.17")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.8.17");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
