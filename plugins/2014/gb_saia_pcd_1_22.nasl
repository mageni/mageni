###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_saia_pcd_1_22.nasl 12260 2018-11-08 12:46:52Z cfischer $
#
# Saia PCD < 1.22 Multiple Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2014 Greenbone Networks GmbH
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

CPE_PREFIX = "cpe:/h:saia_burgess_controls";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103895");
  script_version("$Revision: 12260 $");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Saia PCD < 1.22 Multiple Vulnerabilities");

  script_xref(name:"URL", value:"http://www.sbc-support.com/de/product-index/firmware-for-pcd-cosinus.html");
  script_xref(name:"URL", value:"http://www.heise.de/security/meldung/Kritische-Schwachstelle-in-hunderten-Industrieanlagen-1854385.html");
  script_xref(name:"URL", value:"http://www.heise.de/security/meldung/Verwundbare-Industrieanlagen-Fernsteuerbares-Gotteshaus-1902245.html");

  script_tag(name:"last_modification", value:"$Date: 2018-11-08 13:46:52 +0100 (Thu, 08 Nov 2018) $");
  script_tag(name:"creation_date", value:"2014-01-28 11:22:01 +0100 (Tue, 28 Jan 2014)");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("General");
  script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("gb_saia_pcd_web_detect.nasl");
  script_mandatory_keys("saia_pcd/detected", "saia_pcd/version");

  script_tag(name:"impact", value:"Exploiting these issue could allow an attacker to compromise the
  application, access or modify data.");

  script_tag(name:"vuldetect", value:"Check the firmware version.");

  script_tag(name:"insight", value:"The firmware of the remote Saia PCD is older then 1.22.x");

  script_tag(name:"solution", value:"Update firmware to 1.22.x");

  script_tag(name:"summary", value:"Saia PCD is prone to a vulnerability in the user authentication.");

  script_tag(name:"affected", value:"Saia PCD with firmware < 1.22.x");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_port_from_cpe_prefix(cpe: CPE_PREFIX, first_cpe_only: TRUE))
  exit(0);

port = infos["port"];
CPE = infos["cpe"];

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less (version: version, test_version: "1.22") ) {
    report = report_fixed_ver(installed_version: version, fixed_version: "1.22");
    security_message (port: port, data: report);
    exit(0);
}

exit(99);