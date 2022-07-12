##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_riverbed_steelhead_file_read_vuln.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# Riverbed SteelHead Arbitrary File Read Vulnerability
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

CPE = "cpe:/a:riverbed:steelhead";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106846");
  script_version("$Revision: 12106 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-06-06 08:53:41 +0700 (Tue, 06 Jun 2017)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("Riverbed SteelHead Arbitrary File Read Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_riverbed_steelhead_ssh_detect.nasl", "gb_riverbed_steelhead_http_detect.nasl");
  script_mandatory_keys("riverbed/steelhead/detected");

  script_tag(name:"summary", value:"Riverbed SteelHead VCX is prone to an authenticated arbitrary file read
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Riverbed Steelhead VCX 9.6.0a");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the
  disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to
  upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/42101/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

model = get_kb_item("riverbed/steelhead/model");

if (!model || model !~ "^VCX")
  exit(0);

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version == "9.6.0a") {
  report = report_fixed_ver(installed_version: version, fixed_version: "WillNotFix");
  security_message(port: 0, data: report);
  exit(0);
}

exit(0);
