###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_qnap_qts_comm_inj.nasl 12260 2018-11-08 12:46:52Z cfischer $
#
# QNAP QTS Command Injection Vulnerability
#
# Authors:
# Tameem Eissa <tameem.eissa@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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

CPE_PREFIX = "cpe:/h:qnap";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107275");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_version("$Revision: 12260 $");

  script_name("QNAP QTS Command Injection Vulnerability");

  script_xref(name:"URL", value:"https://www.lateralsecurity.com/downloads/Lateral_Security-Advisory-QNAP_QTS_CVE-2017-10700.pdf");
  script_xref(name:"URL", value:"https://www.qnap.com/de-de/security-advisory/nas-201709-11");

  script_cve_id("CVE-2017-10700");

  script_tag(name:"last_modification", value:"$Date: 2018-11-08 13:46:52 +0100 (Thu, 08 Nov 2018) $");
  script_tag(name:"creation_date", value:"2017-12-13 13:24:30 +0100 (Wed, 13 Dec 2017)");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("gb_qnap_nas_detect.nasl");
  script_require_ports("Services/www", 80, 8080);
  script_mandatory_keys("qnap/qts", "qnap/version", "qnap/build");

  script_tag(name:"vuldetect", value:"Check the firmware version");
  script_tag(name:"solution", value:"Update QTS 4.2.6 build 20170905 or QTS 4.3.3.0262 build 20170727.");

  script_tag(name:"summary", value:"QNAP QTS is vulnerable to command injection vulnerability.");

  script_tag(name:"insight", value:"The media library service fails to sufficiently sanitise user inputs.");

  script_tag(name:"impact", value:"A remote, un-authenticated attacker can provide inputs to this service
  which executes system commands in the context of the 'admin' user of the QNAP device.");

  script_tag(name:"affected", value:"QNAP QTS versions 4.3.x before 4.3.3.0262 build 20170727 and
  4.2.x before QTS 4.2.6 build 20170905.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if (!infos = get_app_port_from_cpe_prefix(cpe: CPE_PREFIX, first_cpe_only: TRUE)) exit(0);

port = infos["port"];
CPE = infos["cpe"];

# TODO: Use get_app_version() and make sure it returns the version as well as the build
if (!version = get_kb_item("qnap/version")) exit(0);
if (!build = get_kb_item("qnap/build")) exit(0);

V = version + '.' + build;

if (version =~ "^4\.3\.")
{
  if (version_is_less(version: V, test_version: "4.3.3.20170727"))
  {
    report = report_fixed_ver(installed_version: version, installed_build: build,
                              fixed_version: '4.3.3', fixed_build: '20170727');
    security_message(port:port, data:report);
    exit(0);
  }
}
else if (version =~ "^4\.2\.")
{
  if (version_is_less(version: V, test_version: "4.2.6.20170905"))
  {
    report = report_fixed_ver(installed_version: version, installed_build: build,
                              fixed_version: '4.2.6', fixed_build: '20170905');
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);