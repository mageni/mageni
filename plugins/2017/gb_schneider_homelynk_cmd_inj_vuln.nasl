###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_schneider_homelynk_cmd_inj_vuln.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# Schneider Electric homeLYnk Command Injection Vulnerability
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

CPE = "cpe:/a:schneider_electric:homelynk";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106746");
  script_version("$Revision: 12106 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-04-12 14:05:46 +0200 (Wed, 12 Apr 2017)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2017-7689");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Schneider Electric homeLYnk Command Injection Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_schneider_homelynk_controller_detect.nasl");
  script_mandatory_keys("schneider_homelynk/detected");

  script_tag(name:"summary", value:"Schneider Electric homeLYnk Controller is prone to a command injection
vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The homeLYnk controller is susceptible to a command injection attack.");

  script_tag(name:"affected", value:"Schneider Electric homeLYnk Controller prior to version 1.5.0.");

  script_tag(name:"solution", value:"Update the firmware to version 1.5.0 or later.");

  script_xref(name:"URL", value:"http://download.schneider-electric.com/files?p_Doc_Ref=SEVD-2017-052-02");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "1.5.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.5.0");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
