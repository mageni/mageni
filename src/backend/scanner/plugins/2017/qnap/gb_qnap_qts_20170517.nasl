###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_qnap_qts_20170517.nasl 12260 2018-11-08 12:46:52Z cfischer $
#
# QNAP QTS Multiple Vulnerabilities
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

CPE_PREFIX = "cpe:/h:qnap";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106880");
  script_version("$Revision: 12260 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-08 13:46:52 +0100 (Thu, 08 Nov 2018) $");
  script_tag(name:"creation_date", value:"2017-06-16 16:07:13 +0700 (Fri, 16 Jun 2017)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2017-7629");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("QNAP QTS Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_qnap_nas_detect.nasl");
  script_mandatory_keys("qnap/qts", "qnap/version", "qnap/build");

  script_tag(name:"summary", value:"QNAP QTS is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"QNAP QTS before QTS 4.2.6 build 20170607 and before QTS 4.3.3.0210 Build
  20170606");

  script_tag(name:"solution", value:"Update to QTS 4.2.6 build 20170607, QTS 4.3.3.0210 Build 20170606 or
  later.");

  script_xref(name:"URL", value:"https://www.qnap.com/en-us/releasenotes/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_port_from_cpe_prefix(cpe: CPE_PREFIX, first_cpe_only: TRUE))
  exit(0);

port = infos["port"];
CPE = infos["cpe"];

# TODO: Use get_app_version() and make sure it returns the version as well as the build
if (!version = get_kb_item("qnap/version"))
  exit(0);

if (!build = get_kb_item("qnap/build"))
  exit(0);

checkvers = version + '.' + build;

if (version_is_less(version: checkvers, test_version: "4.2.6.20170607")) {
  report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "4.2.6",
                            fixed_build: "20170607");
  security_message(port: port, data: report);
  exit(0);
}

if (version =~ "^4\.3\.") {
  if (version_is_less(version: checkvers, test_version: "4.3.3.20170606")) {
    report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "4.3.3",
                              fixed_build: "20170606");
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);