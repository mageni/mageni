###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_bugzilla_mult_vuln.nasl 12096 2018-10-25 12:26:02Z asteins $
#
# Bugzilla Multiple Vulnerabilities
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

CPE = 'cpe:/a:mozilla:bugzilla';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106164");
  script_version("$Revision: 12096 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-25 14:26:02 +0200 (Thu, 25 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-08-02 08:27:33 +0700 (Tue, 02 Aug 2016)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_cve_id("CVE-2015-8508", "CVE-2015-8509");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Bugzilla Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("bugzilla_detect.nasl");
  script_mandatory_keys("bugzilla/installed");

  script_tag(name:"summary", value:"Bugzilla is prone to multiple vulnerabilities.");


  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Bugzilla is prone to multiple vulnerabilities:

Cross-site scripting vulnerability in showdependencygraph.cgi when a local dot configuration is used, allows
remote attackers to inject arbitrary web script or HTML via a crafted bug summary. (CVE-2015-8508)

Template.pm does not properly construct CSV files, which allows remote attackers to obtain sensitive
information by leveraging a web browser that interprets CSV data as JavaScript code. (CVE-2015-8509)");

  script_tag(name:"impact", value:"An attacker may obtain sensitive information or inject arbitrary web
script or HTML.");

  script_tag(name:"affected", value:"Bugzilla 2.x, 3.x, and 4.x before 4.2.16, 4.3.x and 4.4.x before 4.4.11,
and 4.5.x and 5.0.x before 5.0.2");

  script_tag(name:"solution", value:"Upgrade to Version 4.2.16, 4.4.11, 5.0.2 or later.");

  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2015/Dec/131");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "4.2.16")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.2.16");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.3.0", test_version2: "4.4.10")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.4.11");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.5.0", test_version2: "5.0.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.0.2");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
