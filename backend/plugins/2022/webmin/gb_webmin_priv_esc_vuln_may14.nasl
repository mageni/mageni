# Copyright (C) 2022 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
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

CPE = "cpe:/a:webmin:webmin";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127014");
  script_version("2022-05-25T06:53:38+0000");
  script_tag(name:"last_modification", value:"2022-05-25 10:18:04 +0000 (Wed, 25 May 2022)");
  script_tag(name:"creation_date", value:"2022-05-18 13:54:35 +0000 (Wed, 18 May 2022)");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");

  script_cve_id("CVE-2022-30708");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Webmin <= 1.991 Privilege Escalation Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Privilege escalation");
  script_dependencies("webmin.nasl");
  script_mandatory_keys("webmin/installed");

  script_tag(name:"summary", value:"Webmin is prone to a privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Webmin, when the Authentic theme is used, allows remote code
  execution when a user has been manually created (i.e., not created in Virtualmin or Cloudmin).
  This occurs because settings-editor_write.cgi does not properly restrict the file parameter.");

  script_tag(name:"affected", value:"Webmin version 1.991 and prior.");

  script_tag(name:"solution", value:"Update to version 1.994 or later.");

  script_xref(name:"URL", value:"https://github.com/esp0xdeadbeef/rce_webmin");
  script_xref(name:"URL", value:"https://github.com/webmin/webmin/issues/1635");
  script_xref(name:"URL", value:"https://www.webmin.com/security.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

# nb: There was no version 1.992 or 1.993 in between according to https://webmin.com/changes.html
if (version_is_less_equal(version: version, test_version: "1.991")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.994", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
