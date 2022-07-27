###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_couchdb_priv_esc_vuln_win.nasl 13750 2019-02-19 07:33:36Z mmartin $
#
# Apache CouchDB < 2.3.0 Remote Privilege Escalation Vulnerability (Windows)
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
#
# Copyright:
# Copyright (C) 2019 Greenbone Networks GmbH
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112476");
  script_version("$Revision: 13750 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-19 08:33:36 +0100 (Tue, 19 Feb 2019) $");
  script_tag(name:"creation_date", value:"2019-01-03 11:36:11 +0100 (Thu, 03 Jan 2019)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_cve_id("CVE-2018-17188");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache CouchDB < 2.3.0 Remote Privilege Escalation Vulnerability (Windows)");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_couchdb_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("couchdb/installed", "Host/runs_windows");

  script_tag(name:"summary", value:"This host is running CouchDB and is prone to a remote privilege escalation vulnerability.");
  script_tag(name:"insight", value:"CouchDB allowed for runtime-configuration of key components of the database.
  In some cases, this lead to vulnerabilities where CouchDB admin users could access the underlying operating system as the CouchDB user.");
  script_tag(name:"impact", value:"Together with other vulnerabilities, it allowed full system entry for unauthenticated users.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"affected", value:"Apache CouchDB through version 2.2.0.");
  script_tag(name:"solution", value:"Update to version 2.3.0 or later.");

  script_xref(name:"URL", value:"https://blog.couchdb.org/2018/12/17/cve-2018-17188/");

  exit(0);
}

CPE = "cpe:/a:apache:couchdb";

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: cpe, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "2.3.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.3.0");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
