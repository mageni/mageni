###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_qnap_qts_20170729.nasl 6823 2017-08-01 04:55:14Z ckuersteiner $
#
# QNAP QTS Multiple Vulnerabilities
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
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

CPE = "cpe:/h:qnap";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140260");
  script_version("$Revision: 6823 $");
  script_tag(name: "last_modification", value: "$Date: 2017-08-01 06:55:14 +0200 (Tue, 01 Aug 2017) $");
  script_tag(name: "creation_date", value: "2017-08-01 10:17:13 +0700 (Tue, 01 Aug 2017)");
  script_tag(name: "cvss_base", value: "7.5");
  script_tag(name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2017-7876", "CVE-2017-11103", "CVE-2017-1000364");

  script_tag(name: "qod_type", value: "remote_banner");

  script_tag(name: "solution_type", value: "VendorFix");

  script_name("QNAP QTS Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_qnap_nas_detect.nasl");
  script_mandatory_keys("qnap/qts","qnap/version","qnap/build");

  script_tag(name: "summary", value: "QNAP QTS is prone to multiple vulnerabilities.");

  script_tag(name: "insight", value: "QNAP QTS is prone to multiple vulnerabilities:

- Multiple vulnerabilities regarding OpenVPN.

- Multiple OS command injection vulnerabilities. (CVE-2017-7876)

- Vulnerability in ActiveX controls that could allow for arbitrary code execution on the web client.

- XSS vulnerability in Storage Manager and Backup Station.

- 'Orpheus' Lyre' vulnerability in Samba that could be exploited to bypass authentication mechanisms.
(CVE-2017-11103)

- Vulnerability in the Linux kernel that could be exploited to circumvent the stack guard page.
(CVE-2017-1000364)");

  script_tag(name: "vuldetect", value: "Checks the version.");

  script_tag(name: "affected", value: "QNAP QTS before QTS 4.2.6 build 20170729 and before QTS 4.3.3.0262 build
20170727");

  script_tag(name: "solution", value: "Update to QTS 4.2.6 build 20170729, QTS 4.3.3.0262 build 20170727 or
later.");

  script_xref(name: "URL", value: "https://www.qnap.com/en-us/releasenotes/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port_from_cpe_prefix(cpe: CPE))
  exit(0);

if (!version = get_kb_item("qnap/version"))
  exit(0);

if (!build = get_kb_item("qnap/build"))
  exit(0);

checkvers = version + '.' + build;

if (version_is_less(version: checkvers, test_version: "4.2.6.20170729")) {
  report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "4.2.6",
                            fixed_build: "20170729");
  security_message(port: port, data: report);
  exit(0);
}

if (version =~ "^4\.3\.") {
  if (version_is_less(version: checkvers, test_version: "4.3.3.20170727")) {
    report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "4.3.3",
                              fixed_build: "20170727");
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
