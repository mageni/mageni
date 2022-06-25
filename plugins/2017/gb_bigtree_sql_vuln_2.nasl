###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_bigtree_sql_vuln_2.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# BigTree CMS SQL Injection Vulnerability (2)
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH
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

CPE = "cpe:/a:bigtree:bigtree";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112141");
  script_version("$Revision: 12106 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-11-28 08:33:19 +0100 (Tue, 28 Nov 2017)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");

  script_cve_id("CVE-2017-16961");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("BigTree CMS SQL Injection Vulnerability (2)");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_bigtree_detect.nasl");
  script_mandatory_keys("BigTree/Installed");

  script_tag(name:"summary", value:"BigTree CMS is prone to an SQL injection vulnerability.");

  script_tag(name:"insight", value:"An SQL injection vulnerability in core/inc/auto-modules.php in BigTree CMS allows
remote authenticated attackers to obtain information in the context of the user used by the application to retrieve data from the database.
The attack uses an admin/trees/add/process request with a crafted _tags[] parameter that is mishandled in a later admin/ajax/dashboard/approve-change request.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"Update to version 4.2.20 or later.");

  script_xref(name:"URL", value:"https://github.com/bigtreecms/BigTree-CMS/issues/323");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less_equal(version: version, test_version: "4.2.19")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.2.20");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
