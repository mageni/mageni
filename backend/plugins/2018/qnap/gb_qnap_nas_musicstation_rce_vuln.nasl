###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_qnap_nas_musicstation_rce_vuln.nasl 13032 2019-01-11 07:56:51Z mmartin $
#
# QNAP QTS Music Station < 5.1.3 RCE Vulnerability
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

CPE = "cpe:/a:qnap:music_station";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141489");
  script_version("$Revision: 13032 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-11 08:56:51 +0100 (Fri, 11 Jan 2019) $");
  script_tag(name:"creation_date", value:"2018-09-18 15:13:19 +0700 (Tue, 18 Sep 2018)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2018-0718");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("QNAP QTS Music Station < 5.1.3 RCE Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_qnap_nas_musicstation_detect.nasl");
  script_mandatory_keys("qnap_musicstation/detected");

  script_tag(name:"summary", value:"Command injection vulnerability in Music Station could allow remote attackers
to run arbitrary commands in the compromised application.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Music Station 5.1.2 and earlier.");

  script_tag(name:"solution", value:"Update to version 5.1.3 or later.");

  script_xref(name:"URL", value:"https://www.qnap.com/zh-tw/security-advisory/nas-201809-14");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "5.1.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.1.3");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
