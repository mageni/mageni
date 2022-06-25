###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hp_ilo_mult_vuln.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# HP Integrated Lights-Out 4 Multiple Remote Vulnerabilities
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

CPE = "cpe:/o:hp:integrated_lights-out_4_firmware";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140325");
  script_version("$Revision: 12106 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-08-25 09:17:16 +0700 (Fri, 25 Aug 2017)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2017-12542");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("HP Integrated Lights-Out 4 Multiple Remote Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("ilo_detect.nasl");
  script_mandatory_keys("HP_ILO/installed");

  script_tag(name:"summary", value:"HP Integrated Lights-Out 4 is prone to multiple remote vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A potential security vulnerability has been identified in HPE Integrated
Lights-out (iLO 4). The vulnerability could be exploited remotely to allow authentication bypass and execution of
code.");

  script_tag(name:"affected", value:"HPE Integrated Lights-Out 4 (iLO 4) prior to v2.53.");

  script_tag(name:"solution", value:"HPE has provided firmware updates to resolve this vulnerability. iLO 4
version v2.53 or newer.");

  script_xref(name:"URL", value:"http://h20565.www2.hpe.com/hpsc/doc/public/display?docId=hpesbhf03769en_us");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "2.53")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.53");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
