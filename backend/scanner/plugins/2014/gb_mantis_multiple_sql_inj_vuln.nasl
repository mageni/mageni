###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mantis_multiple_sql_inj_vuln.nasl 12818 2018-12-18 09:55:03Z ckuersteiner $
#
# MantisBT Multiple SQL Injection Vulnerabilities
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:mantisbt:mantisbt";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105902");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_version("$Revision: 12818 $");

  script_name("MantisBT Multiple SQL Injection Vulnerabilities");

  script_bugtraq_id(65445, 65461);
  script_cve_id("CVE-2014-1608", "CVE-2014-1609");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65445");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65461");
  script_xref(name:"URL", value:"http://www.mantisbt.org/bugs/view.php?id=16879");
  script_xref(name:"URL", value:"http://www.mantisbt.org/bugs/view.php?id=16880");

  script_tag(name:"last_modification", value:"$Date: 2018-12-18 10:55:03 +0100 (Tue, 18 Dec 2018) $");
  script_tag(name:"creation_date", value:"2014-03-25 11:38:14 +0700 (Tue, 25 Mar 2014)");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("mantis_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("mantisbt/detected");

  script_tag(name:"summary", value:"There are multiple SQL Injection vulnerabilities in MantisBT which allow
  a remote attacker to access or modify data.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"Upgrade to version 1.2.16 or higher.");

  script_tag(name:"insight", value:"Use of db_query() instead of db_query_bound() allowed SQL injection
  attacks due to unsanitized use of parameters within the query when using
  the SOAP API mc_project_get_attachments, news_get_limited_rows, summary_print_by_enum,
  summary_print_by_age, summary_print_by_developer, summary_print_by_reporter, summary_print_by_category,
  create_bug_enum_summary, enum_bug_group function and mc_issue_attachment_get.");

  script_tag(name:"affected", value:"MantisBT Version 1.2.15 and prior.");

  script_tag(name:"impact", value:"A remote attacker can compromise the application, access or modify data,
  or exploit latent vulnerabilities in the underlying database.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");
  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe:CPE))
  exit(0);

if (!vers = get_app_version(cpe:CPE, port:port))
  exit(0);

if (version_is_less(version:vers, test_version:"1.2.16")) {
  report = report_fixed_ver(installed_version: vers, fixed_version: "1.2.16");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
