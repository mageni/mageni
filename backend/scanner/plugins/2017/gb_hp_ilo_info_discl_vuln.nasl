###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hp_ilo_info_discl_vuln.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# HP Integrated Lights-Out 3 Information Disclosure Vulnerability
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

CPE = "cpe:/o:hp:integrated_lights-out_3_firmware";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106493");
  script_version("$Revision: 12106 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-01-05 12:42:59 +0700 (Thu, 05 Jan 2017)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2016-4379");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("HP Integrated Lights-Out 3 Information Disclosure Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("ilo_detect.nasl");
  script_mandatory_keys("HP_ILO/installed");

  script_tag(name:"summary", value:"HP Integrated Lights-Out 3 is prone to an information disclosure
vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The TLS implementation in HPE Integrated Lights-Out 3 firmware does no
properly use a MAC protection mechanism in conjunction with CBC padding, which allows remote attackers to obtain
sensitive information via a padding-oracle attack, aka a Vaudenay attack.");

  script_tag(name:"affected", value:"HPE Integrated Lights-Out 3 (iLO 3) prior to v1.88.");

  script_tag(name:"solution", value:"HPE has provided firmware updates to resolve this vulnerability. iLO 3
version v1.88 or subsequent.");

  script_xref(name:"URL", value:"https://h20566.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-c05249760");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "1.88")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.88");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
