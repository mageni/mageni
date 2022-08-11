##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_piwigo_sql_inj_dec17.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# Piwigo Sql Injection Vulnerability
#
# Authors:
# Tameem Eissa <tameem.eissa@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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

CPE = 'cpe:/a:piwigo:piwigo';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107271");
  script_version("$Revision: 12106 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-12-11 11:11:04 +0700 (Mon, 11 Dec 2017)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");

  script_cve_id("CVE-2017-16893", "CVE-2018-6883");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Piwigo Sql Injection Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_piwigo_detect.nasl");
  script_mandatory_keys("piwigo/installed");

  script_tag(name:"summary", value:"Piwigo is prone to sql injection vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Values of the edit_list parameters are not sanitized. These are used to construct an SQL query and retrieve a list of registered users into the application.

  Another sql injection is possible in admin/tags.php in the administration panel, via the tags array parameter in an admin.php?page=tags request. The attacker must be an administrator.");

  script_tag(name:"affected", value:"Piwigo version 2.9.2 and prior.");

  script_tag(name:"solution", value:"Update to Piwigo 2.9.3 or later.");

  script_xref(name:"URL", value:"https://www.fortify24x7.com/cve-2017-16893/");
  script_xref(name:"URL", value:"https://github.com/Piwigo/Piwigo/issues/839");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less_equal(version: version, test_version: "2.9.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.9.3");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
