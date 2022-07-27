# Copyright (C) 2018 Greenbone Networks GmbH
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

CPE = "cpe:/a:cesanta:mongoose";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813632");
  script_version("2021-07-07T13:01:23+0000");
  script_cve_id("CVE-2018-10945");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2021-07-07 13:01:23 +0000 (Wed, 07 Jul 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-08-10 14:18:00 +0000 (Fri, 10 Aug 2018)");
  script_tag(name:"creation_date", value:"2018-07-09 14:45:19 +0530 (Mon, 09 Jul 2018)");
  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Mongoose Web Server < 6.12 'mg_handle_cgi' Function DoS Vulnerability");

  script_tag(name:"summary", value:"Mongoose Web Server is prone to a denial of service (DoS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to heap-based buffer over-read error in
  'mg_handle_cgi' function in 'mongoose.c' script.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to cause a DoS.");

  script_tag(name:"affected", value:"Mongoose Web Server version 6.11. Other versions might be
  affected as well.");

  script_tag(name:"solution", value:"Update to version 6.12 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://blog.hac425.top/2018/05/16/CVE-2018-10945-mongoose.html");

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_dependencies("gb_mongoose_web_server_http_detect.nasl");
  script_mandatory_keys("cesanta/mongoose/detected");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];

if(version_in_range(version:vers, test_version:"6.0", test_version2:"6.11")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"6.12", install_path:infos["location"]);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);