# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) of the respective author(s)
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142106");
  script_version("$Revision: 14088 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-11 10:16:32 +0100 (Mon, 11 Mar 2019) $");
  script_tag(name:"creation_date", value:"2019-03-08 11:46:17 +0700 (Fri, 08 Mar 2019)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2018-14695", "CVE-2018-14696", "CVE-2018-14700", "CVE-2018-14703", "CVE-2018-14704");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_name("Drobo NAS Multiple Vulnerabilities in MySQL Web Application");

  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_drobo_nas_consolidation.nasl");
  script_mandatory_keys("drobo/mysqlapp/detected");

  script_tag(name:"summary", value:"Drobo NAS are prone to multiple vulnerabilities in their MySQL Web
Application.");

  script_tag(name:"insight", value:"Drobo NAS are prone to multiple vulnerabilities in their MySQL Web
Application:

  - Unauthenticated Access to MySQL diag.php (CVE-2018-14695)

  - Unauthenticated Access to device info via MySQL API drobo.php (CVE-2018-14696)

  - Unauthenticated Access to MySQL Log Files (CVE-2018-14700)

  - Unauthenticated Access to MySQL Database Password (CVE-2018-14703)

  - Reflected Cross-Site Scripting via MySQL API droboapps.php (CVE-2018-14704)");

  script_tag(name:"solution", value:"No known solution is available as of 11th March, 2019.
  Information regarding this issue will be updated once solution details are available.");

  script_tag(name:"vuldetect", value:"Tries to obtain the root password for MySQL.");

  script_xref(name:"URL", value:"https://blog.securityevaluators.com/call-me-a-doctor-new-vulnerabilities-in-drobo5n2-4f1d885df7fc");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_kb_item("drobo/mysqlapp/port"))
  exit(0);

url = '/mysql/api/droboapp/data';

if (http_vuln_check(port: port, url: url, pattern: '"password":"[0-9a-f]+', check_header: TRUE)) {
  report = report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
