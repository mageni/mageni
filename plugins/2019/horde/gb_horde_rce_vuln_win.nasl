# Copyright (C) 2019 Greenbone Networks GmbH
#
# SPDX-License-Identifier: GPL-2.0-or-later
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

CPE = "cpe:/a:horde:horde_groupware";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142488");
  script_version("2019-06-04T09:20:09+0000");
  script_tag(name:"last_modification", value:"2019-06-04 09:20:09 +0000 (Tue, 04 Jun 2019)");
  script_tag(name:"creation_date", value:"2019-06-04 09:18:45 +0000 (Tue, 04 Jun 2019)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_cve_id("CVE-2019-9858");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_name("Horde Groupware Webmail <= 5.2.22 RCE Vulnerability (Windows)");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("horde_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("horde/installed", "Host/runs_windows");

  script_tag(name:"summary", value:"Horde Groupware Webmail is prone to an authenticated remote code execution
  vulnerability.");

  script_tag(name:"insight", value:"Horde/Form/Type.php contains a vulnerable class that handles image upload in
  forms. When the Horde_Form_Type_image method onSubmit() is called on uploads, it invokes the functions
  getImage() and _getUpload(), which uses unsanitized user input as a path to save the image. The unsanitized POST
  parameter object[photo][img][file] is saved in the $upload[img][file] PHP variable, allowing an attacker to
  manipulate the $tmp_file passed to move_uploaded_file() to save the uploaded file. By setting the parameter to
  (for example) ../usr/share/horde/static/bd.php, one can write a PHP backdoor inside the web root. The static/
  destination folder is a good candidate to drop the backdoor because it is always writable in Horde
  installations.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Horde Groupware Webmail version 5.2.22 and prior.");

  script_tag(name:"solution", value:"No known solution is available as of 04th June, 2019.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://www.ratiosec.com/2019/horde-groupware-webmail-authenticated-arbitrary-file-injection-to-rce/");
  script_xref(name:"URL", value:"https://ssd-disclosure.com/archives/3814/ssd-advisory-horde-groupware-webmail-authenticated-arbitrary-file-injection-to-rce");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos['version'];
path = infos['location'];

if (version_is_less_equal(version: version, test_version: "5.2.22")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "None", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
