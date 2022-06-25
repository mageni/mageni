###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_manageengine_appli_manager_sql_inj_vul.nasl 12228 2018-11-06 12:52:41Z cfischer $
#
# ManageEngine Applications Manager SQL Injection Vulnerability
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

CPE = "cpe:/a:manageengine:applications_manager";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107251");
  script_version("$Revision: 12228 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-06 13:52:41 +0100 (Tue, 06 Nov 2018) $");
  script_tag(name:"creation_date", value:"2017-11-07 15:43:15 +0700 (Tue, 07 Nov 2017)");

  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2017-16542", "CVE-2017-16543");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("ManageEngine Applications Manager SQL Injection Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_manage_engine_appli_manager_detect.nasl");
  script_mandatory_keys("ManageEngine/Applications/Manager/Installed");

  script_tag(name:"summary", value:"ManageEngine Applications Manager is prone to a SQL injection
vulnerability.");

  script_tag(name:"insight", value:"ManageEngine Applications Manager is vulnerable to SQL injection via the
name parameter in a manageApplications.do request and via GraphicalView.do, as demonstrated by a
crafted viewProps yCanvas field or viewid parameter.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"ManageEngine Applications Manager 13.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_xref(name:"URL", value:"https://code610.blogspot.de/2017/11/sql-injection-in-manageengine.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version =~ "^13.*")
{
    if (version_is_less_equal(version: version, test_version: "13430"))
    {
      report = report_fixed_ver(installed_version: version, fixed_version: "NoneAvailable");
      security_message(port: port, data: report);
      exit(0);
    }
}

exit(99);
