###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hp_service_manager_rce_vuln.nasl 12365 2018-11-15 10:30:55Z ckuersteiner $
#
# HP Service Manager Remote Command Execution Vulnerability
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

CPE = "cpe:/a:hp:service_manager";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106144");
  script_version("$Revision: 12365 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-15 11:30:55 +0100 (Thu, 15 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-07-18 11:48:16 +0700 (Mon, 18 Jul 2016)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2016-1998");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("HP Service Manager Remote Command Execution Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_hp_service_manager_detect.nasl");
  script_mandatory_keys("hp_service_manager/detected");

  script_tag(name:"summary", value:"HP Service Manager is prone to a remote command execution vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A remote attacker may execute arbitrary commands via a crafted serialized
Java object, related to the Apache Commons Collections library.");

  script_tag(name:"impact", value:"A remote attacker may execute arbitrary commands.");

  script_tag(name:"affected", value:"Versions 9.30, 9.31, 9.32, 9.33, 9.34, 9.35, 9.40, and 9.41");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://h20564.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-c05054565");


  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range(version: version, test_version: "9.30.0000", test_version2: "9.35.0000") ||
    version_in_range(version: version, test_version: "9.40.0000", test_version2: "9.41.0000")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
