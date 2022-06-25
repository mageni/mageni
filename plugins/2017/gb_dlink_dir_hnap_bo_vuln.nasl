###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dlink_dir_hnap_bo_vuln.nasl 12482 2018-11-22 09:19:38Z cfischer $
#
# D-Link DIR Routers HNAP Buffer Overflow Vulnerability
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106587");
  script_version("$Revision: 12482 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-22 10:19:38 +0100 (Thu, 22 Nov 2018) $");
  script_tag(name:"creation_date", value:"2017-02-14 13:49:17 +0700 (Tue, 14 Feb 2017)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2016-6563");
  script_name("D-Link DIR Routers HNAP Buffer Overflow Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_dlink_dir_detect.nasl");
  script_mandatory_keys("Host/is_dlink_dir_device", "d-link/dir/fw_version", "d-link/dir/hw_version");

  script_tag(name:"summary", value:"Several D-Link DIR Routers are prone to a buffer overflow vulnerability in
  HNAP.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable firmware version is present on the target host.");

  script_tag(name:"insight", value:"Processing malformed SOAP messages when performing the HNAP Login action
  causes a buffer overflow in the stack. The vulnerable XML fields within the SOAP body are: Action, Username,
  LoginPassword, and Captcha.");

  script_tag(name:"affected", value:"D-Link DIR-885L, DIR-895L, DIR-890L, DIR-880L, DIR-868L, DIR-869, DIR-879,
  DIR-859, DIR-822, DIR-823, DIR-818L.");

  script_tag(name:"solution", value:"Upgrade to the latest firmware. Please see the references for more info.");

  script_xref(name:"URL", value:"http://supportannouncement.us.dlink.com/announcement/publication.aspx?name=SAP10066");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/o:d-link:dir-895l_firmware",
"cpe:/o:d-link:dir-890l_firmware",
"cpe:/o:d-link:dir-885l_firmware",
"cpe:/o:d-link:dir-880l_firmware",
"cpe:/o:d-link:dir-879_firmware",
"cpe:/o:d-link:dir-869_firmware",
"cpe:/o:d-link:dir-868l_firmware",
"cpe:/o:d-link:dir-859_firmware",
"cpe:/o:d-link:dir-823_firmware",
"cpe:/o:d-link:dir-822_firmware",
"cpe:/o:d-link:dir-818l_firmware");

if (!infos = get_single_app_ports_from_list(cpe_list: cpe_list))
  exit(0);

cpe  = infos["cpe"];
port = infos["port"];

if (!version = get_app_version(cpe: cpe, port: port))
  exit(0);

hw_version = get_kb_item("d-link/dir/hw_version");
if (!hw_version)
  exit(0);

if (cpe == "cpe:/o:d-link:dir-885l_firmware" || cpe == "cpe:/o:d-link:dir-895l_firmware") {
  if (hw_version == "A1" && version_is_less(version: version, test_version: "1.12")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "1.12", extra: "Hardware revision: " + hw_version);
    security_message(port: port, data: report);
  }
  exit(0);
}

if (cpe == "cpe:/o:d-link:dir-890l_firmware") {
  if (hw_version == "A1" && version_is_less(version: version, test_version: "1.11b01")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "1.11b01_beta01_g97i", extra: "Hardware revision: " + hw_version);
    security_message(port: port, data: report);
  }
  exit(0);
}

if (cpe == "cpe:/o:d-link:dir-880l_firmware") {
  if (hw_version == "A1" && version_is_less(version: version, test_version: "1.08WWb04")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "1.08WWb04", extra: "Hardware revision: " + hw_version);
    security_message(port: port, data: report);
  }
  exit(0);
}

if (cpe == "cpe:/o:d-link:dir-879_firmware") {
  if (hw_version == "A1" && version_is_less(version: version, test_version: "1.04")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "1.04", extra: "Hardware revision: " + hw_version);
    security_message(port: port, data: report);
  }
  exit(0);
}

if (cpe == "cpe:/o:d-link:dir-869_firmware") {
  if (hw_version == "A1" && version_is_less(version: version, test_version: "1.03")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "1.03", extra: "Hardware revision: " + hw_version);
    security_message(port: port, data: report);
  }
  exit(0);
}

if (cpe == "cpe:/o:d-link:dir-868l_firmware") {
  if (hw_version == "B1" && version_is_less(version: version, test_version: "2.05b01")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2.05b01", extra: "Hardware revision: " + hw_version);
    security_message(port: port, data: report);
  }
  if (hw_version == "A1" && version_is_less(version: version, test_version: "1.12WWb04")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "1.12WWb04", extra: "Hardware revision: " + hw_version);
    security_message(port: port, data: report);
  }
  exit(0);
}

if (cpe == "cpe:/o:d-link:dir-859_firmware") {
  if (hw_version == "A1" && version_is_less(version: version, test_version: "1.06")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "1.06", extra: "Hardware revision: " + hw_version);
    security_message(port: port, data: report);
  }
  exit(0);
}

if (cpe == "cpe:/o:d-link:dir-823_firmware") {
  if (hw_version == "A1" && version_is_less(version: version, test_version: "1.00WWb06")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "1.00WWb06", extra: "Hardware revision: " + hw_version);
    security_message(port: port, data: report);
  }
  exit(0);
}

if (cpe == "cpe:/o:d-link:dir-822_firmware") {
  if (hw_version == "B1" && version_is_less(version: version, test_version: "2.03WWb01")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2.03WWb01", extra: "Hardware revision: " + hw_version);
    security_message(port: port, data: report);
  }
  exit(0);
}

if (cpe == "cpe:/o:d-link:dir-818l_firmware") {
  if (hw_version == "B1" && version_is_less(version: version, test_version: "2.05")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2.05 beta 08", extra: "Hardware revision: " + hw_version);
    security_message(port: port, data: report);
  }
  exit(0);
}

exit(0);