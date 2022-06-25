###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_zoneminder_obj_inj_vuln.nasl 13561 2019-02-11 07:33:41Z mmartin $
#
# ZoneMinder < 1.32.3 Object Injection Vulnerability
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112470");
  script_version("$Revision: 13561 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-11 08:33:41 +0100 (Mon, 11 Feb 2019) $");
  script_tag(name:"creation_date", value:"2018-12-21 15:31:10 +0100 (Fri, 21 Dec 2018)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2018-1000832", "CVE-2018-1000833");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("ZoneMinder < 1.32.3 Object Injection Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_zoneminder_detect.nasl");
  script_mandatory_keys("zoneminder/installed");

  script_tag(name:"summary", value:"ZoneMinder is prone to an object injection vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"PHP Object Deserialization Injection attacks utilise the unserialize
  function within PHP. The deserialisation of the PHP object can trigger certain methods within the object,
  allowing the attacker to perform unauthorised actions like execution of code, disclosure of information, etc.

  The ZoneMinder project overly trusted user input when processing the data obtained from a form.");
  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to perform unauthorised operating system commands on the target server.");
  script_tag(name:"affected", value:"ZoneMinder through version 1.32.2.");
  script_tag(name:"solution", value:"Update to ZoneMinder version 1.32.3 or later.");

  script_xref(name:"URL", value:"https://github.com/ZoneMinder/zoneminder/releases");
  script_xref(name:"URL", value:"https://0dd.zone/2018/10/28/zoneminder-Object-Injection/");
  script_xref(name:"URL", value:"https://0dd.zone/2018/10/28/zoneminder-Object-Injection-2/");
  script_xref(name:"URL", value:"https://github.com/ZoneMinder/zoneminder/issues/2271");
  script_xref(name:"URL", value:"https://github.com/ZoneMinder/zoneminder/issues/2272");

  exit(0);
}

CPE = "cpe:/a:zoneminder:zoneminder";

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe: CPE))
  exit(0);

if(!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if(version_is_less(version: version, test_version: "1.32.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.32.3");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);