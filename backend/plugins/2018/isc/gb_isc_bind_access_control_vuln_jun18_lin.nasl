###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_isc_bind_access_control_vuln_jun18_lin.nasl 12116 2018-10-26 10:01:35Z mmartin $
#
# ISC BIND Access Control Vulnerability - Jun18 (Linux)
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

CPE = 'cpe:/a:isc:bind';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141179");
  script_version("$Revision: 12116 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 12:01:35 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-06-13 11:46:01 +0700 (Wed, 13 Jun 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2018-5738");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"Workaround");

  script_name("ISC BIND Access Control Vulnerability - Jun18 (Linux)");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("bind_version.nasl", "os_detection.nasl");
  script_mandatory_keys("ISC BIND/installed", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Some versions of BIND can improperly permit recursive query service to
unauthorized clients.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"ISC BIND 9.9.12, 9.10.7, 9.11.3, 9.12.0->9.12.1-P2, 9.13.0, 9.9.12-S1,
9.10.7-S1, 9.11.3-S1, and 9.11.3-S2 on Linux.");

  script_tag(name:"solution", value:"See the vendor advisory for workarounds.");

  script_xref(name:"URL", value:"https://kb.isc.org/article/AA-01616");

  exit(0);
}

include("host_details.inc");
include("revisions-lib.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_proto(cpe: CPE, port: port))
  exit(0);

version = infos["version"];
proto = infos["proto"];

affected = make_list('9.9.12',
                     '9.10.7',
                     '9.11.3',
                     '9.13.0',
                     '9.9.12.S1',
                     '9.10.7.S1',
                     '9.11.3.S1',
                     '9.11.3.S2');

foreach af (affected) {
  if (version == af) {
    report = report_fixed_ver(installed_version: version, fixed_version: "Workaround");
    security_message(port: port, data: report, proto: proto);
    exit(0);
  }
}

if (version_in_range(version: version, test_version: "9.12.0", test_version2: "9.12.1.P2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "Workaround");
  security_message(port: port, data: report, proto: proto);
  exit(0);
}

exit(0);
