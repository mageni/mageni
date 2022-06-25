##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_asustor_adm_auth_bypass_vuln.nasl 12291 2018-11-09 14:55:44Z cfischer $
#
# ASUSTOR ADM Authentication Bypass Vulnerability
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

CPE = "cpe:/h:asustor:adm_firmware";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141533");
  script_version("$Revision: 12291 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-09 15:55:44 +0100 (Fri, 09 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-09-28 10:15:18 +0700 (Fri, 28 Sep 2018)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("ASUSTOR ADM Authentication Bypass Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_asustor_adm_detect.nasl");
  script_mandatory_keys("asustor_adm/detected");

  script_tag(name:"summary", value:"ASUSTOR ADM is prone to a authentication bypass vulnerability.");

  script_tag(name:"insight", value:"The vulnerability lies in the web interface of ASUSTOR NAS, in the file
located in /initial/index.cgi, which responsible for initializing the device with your ASUSTOR ID. By abusing
/initial/index.cgi?act=register, it is possible to log in with the administrator privileges without any kind of
authentication.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"affected", value:"ASUSTOR ADM 3.0.5.RDU1 and prior.");

  script_tag(name:"solution", value:"Update to the latest version.");

  script_xref(name:"URL", value:"https://blogs.securiteam.com/index.php/archives/3747");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!get_app_location(cpe: CPE, port: port, nofork: TRUE))
  exit(0);

url = '/initial/index.cgi?act=register';

if (http_vuln_check(port: port, url: url, pattern: "SID = '", check_header: TRUE,
                    extra_check: "STATUS = 'register';")) {
  report = report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
