# Copyright (C) 2016 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

CPE = "cpe:/a:apache:struts";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808538");
  script_version("2021-03-31T14:01:21+0000");
  script_cve_id("CVE-2016-1181", "CVE-2016-1182", "CVE-2015-0899");
  script_bugtraq_id(91068, 91067, 74423);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-04-01 10:13:05 +0000 (Thu, 01 Apr 2021)");
  script_tag(name:"creation_date", value:"2016-11-18 14:43:17 +0530 (Fri, 18 Nov 2016)");
  script_name("Apache Struts 1.x - 1.3.10 Multiple Vulnerabilities - Windows");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_apache_struts_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("apache/struts/detected", "Host/runs_windows");

  script_xref(name:"URL", value:"http://jvn.jp/en/jp/JVN03188560/index.html");
  script_xref(name:"URL", value:"http://jvn.jp/en/jp/JVN65044642/index.html");
  script_xref(name:"URL", value:"http://jvn.jp/en/jp/JVN86448949/index.html");

  script_tag(name:"summary", value:"Apache Struts is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the
  target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An 'actionServlet.java' script mishandles multithreaded access to an ActionForm
  instance.

  - An 'actionServlet.java' script does not properly restrict the Validator configuration.

  - An error in the MultiPageValidator implementation.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to
  execute arbitrary code or cause a denial of service or conduct cross-site scripting or
  bypass intended access restrictions.");

  script_tag(name:"affected", value:"Apache Struts 1.0 through 1.3.10.");

  script_tag(name:"solution", value:"No known solution was made available for at least one
  year since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(isnull(port = get_app_port(cpe:CPE)))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];

if(version_in_range(version:vers, test_version:"1.0", test_version2:"1.3.10")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"None", install_path:infos["location"]);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);