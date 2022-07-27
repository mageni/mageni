###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dell_drac_94585.nasl 12175 2018-10-31 06:20:00Z ckuersteiner $
#
# Dell iDRAC7 and iDRAC8 Devices Code Injection Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140083");
  script_bugtraq_id(94585);
  script_cve_id("CVE-2016-5685");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-31 07:20:00 +0100 (Wed, 31 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-11-30 13:23:23 +0100 (Wed, 30 Nov 2016)");
  script_version("$Revision: 12175 $");
  script_name("Dell iDRAC7 and iDRAC8 Devices Code Injection Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_dell_drac_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("dell_idrac/installed", "dell_idrac/generation");

  script_xref(name:"URL", value:"http://en.community.dell.com/techcenter/extras/m/white_papers/20443326");

  script_tag(name:"vuldetect", value:"Check the firmware version");

  script_tag(name:"solution", value:"Update to 2.40.40.40 or higher");

  script_tag(name:"summary", value:"Dell iDRAC7 and iDRAC8 devices with firmware before 2.40.40.40 allow
  authenticated users to gain Bash shell access through a string injection.");

  script_tag(name:"affected", value:"Dell iDRAC7 and iDRAC8 devices with firmware before 2.40.40.40");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/a:dell:idrac7", "cpe:/a:dell:idrac8");
if (!infos = get_all_app_ports_from_list(cpe_list: cpe_list))
  exit(0);

port = infos['port'];

generation = get_kb_item("dell_idrac/generation");
if (!generation)
  exit(0);

cpe = "cpe:/a:dell:idrac" + generation;
if (!version = get_app_version(cpe: cpe))
  exit(0);

if (version_is_less(version: version, test_version: "2.40.40.40")) {
  report = report_fixed_ver(installed_version: version, fixed_version: '2.40.40.40');
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
