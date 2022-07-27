###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dotcms_sql_inj_vuln.nasl 12131 2018-10-26 14:03:52Z mmartin $
#
# dotCMS SQL Injection Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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

CPE = "cpe:/a:dotcms:dotcms";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106616");
  script_version("$Revision: 12131 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 16:03:52 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-02-21 15:43:41 +0700 (Tue, 21 Feb 2017)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2017-5344");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("dotCMS SQL Injection Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_dotcms_detect.nasl");
  script_mandatory_keys("dotCMS/installed");

  script_tag(name:"summary", value:"dotCMS is prone to a blind SQL injection vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The findChildrenByFilter() function which is called by the web accessible
path /categoriesServlet performs string interpolation and direct SQL query execution. SQL quote escaping and a
keyword blacklist were implemented in a new class, SQLUtil (main/java/com/dotmarketing/common/util/SQLUtil.java),
as part of the remediation of CVE-2016-8902. However, these can be overcome in the case of the q and inode
parameters to the /categoriesServlet path. Overcoming these controls permits a number of blind boolean SQL
injection vectors in either parameter. The /categoriesServlet web path can be accessed remotely and without
authentication in a default dotCMS deployment.");

  script_tag(name:"affected", value:"Version 3.6.1 and previous versions.");

  script_tag(name:"solution", value:"Update to version 3.6.2 or later.");

  script_xref(name:"URL", value:"http://dotcms.com/security/SI-39");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "3.6.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.6.2");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
