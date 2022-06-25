###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_openemr_db_disc_vuln.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# OpenEMR Database Disclosure Vulnerability
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH
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

CPE = "cpe:/a:open-emr:openemr";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112103");
  script_version("$Revision: 12106 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-11-06 08:35:26 +0200 (Mon, 06 Nov 2017)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2017-16540");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OpenEMR Database Disclosure Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_openemr_detect.nasl");
  script_mandatory_keys("openemr/installed");

  script_tag(name:"summary", value:"OpenEMR is prone to a database disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"OpenEMR before 5.0.0 Patch 5 allows unauthenticated remote database copying
      because setup.php exposes functionality for cloning an existing OpenEMR site to an arbitrary attacker-controlled
      MySQL server via vectors involving a crafted state parameter.");

  script_tag(name:"impact", value:"A successful exploitation will allow the attackers to steal the contents of the backend database: social security numbers, password hashes,
      and any other sensitive data a medical records system database might hold.");

  script_tag(name:"affected", value:"All OpenEMR versions before 5.0.0 Patch 5.");

  script_tag(name:"solution", value:"Upgrade to OpenEMR 5.0.0 Patch 5 or later.");


  script_xref(name:"URL", value:"http://www.open-emr.org/wiki/index.php/OpenEMR_Patches");
  script_xref(name:"URL", value:"https://isears.github.io/jekyll/update/2017/10/28/openemr-database-disclosure.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "5.0.0-5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.0.0-5");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
