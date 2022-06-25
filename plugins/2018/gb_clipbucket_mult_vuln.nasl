###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_clipbucket_mult_vuln.nasl 9028 2018-03-06 04:48:33Z ckuersteiner $
#
# ClipBucket Multiple Vulnerabilities
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH
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

CPE = "cpe:/a:clipbucket_project:clipbucket";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140826");
  script_version("$Revision: 9028 $");
  script_tag(name: "last_modification", value: "$Date: 2018-03-06 05:48:33 +0100 (Tue, 06 Mar 2018) $");
  script_tag(name: "creation_date", value: "2018-02-28 12:21:38 +0700 (Wed, 28 Feb 2018)");
  script_tag(name: "cvss_base", value: "10.0");
  script_tag(name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2018-7666", "CVE-2018-7664", "CVE-2018-7665");

  script_tag(name: "qod_type", value: "remote_banner_unreliable"); # no release version available

  script_tag(name: "solution_type", value: "VendorFix");

  script_name("ClipBucket Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_clipbucket_detect.nasl");
  script_mandatory_keys("clipbucket/Installed");

  script_tag(name: "summary", value: "ClipBucket is prone to multiple vulnerabilities.");

  script_tag(name: "vuldetect", value: "Checks the version.");

  script_tag(name: "impact", value: "ClipBucket is prone to multiple vulnerabilities:

- Unauthenticated OS Command Injection

- Unauthenticated Arbitrary File Upload

- Unauthenticated Blind SQL Injection");

  script_tag(name: "affected", value: "ClipBucket prior to version 4.0.0 Release 4902.");

  script_tag(name: "solution", value: "Update to version 4.0.0 Release 4902 or later.");

  script_xref(name: "URL", value: "https://www.sec-consult.com/en/blog/advisories/os-command-injection-arbitrary-file-upload-sql-injection-in-clipbucket/index.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less_equal(version: version, test_version: "4.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.0.0 Release 4902");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
