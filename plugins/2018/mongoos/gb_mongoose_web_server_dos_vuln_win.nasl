###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mongoose_web_server_dos_vuln_win.nasl 12959 2019-01-07 11:13:35Z cfischer $
#
# Mongoose Web Server 'mg_handle_cgi' Function Denial of Service Vulnerability (Windows)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:cesanta:mongoose";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813631");
  script_version("$Revision: 12959 $");
  script_cve_id("CVE-2018-10945");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2019-01-07 12:13:35 +0100 (Mon, 07 Jan 2019) $");
  script_tag(name:"creation_date", value:"2018-07-09 14:45:19 +0530 (Mon, 09 Jul 2018)");
  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Mongoose Web Server 'mg_handle_cgi' Function Denial of Service Vulnerability (Windows)");

  script_tag(name:"summary", value:"The host is installed with Mongoose Web Server
  Server and is prone to denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to heap-based buffer over-read
  error in 'mg_handle_cgi' function in 'mongoose.c' script.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to
  cause a denial of service.");

  script_tag(name:"affected", value:"Mongoose version 6.11, other versions might be affected as well.");

  script_tag(name:"solution", value:"Update to version 6.12 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://blog.hac425.top/2018/05/16/CVE-2018-10945-mongoose.html");
  script_xref(name:"URL", value:"https://github.com/cesanta/mongoose/releases");

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_dependencies("gb_mongoose_web_server_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("Cesanta/Mongoose/installed", "Host/runs_windows");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!mongoPort = get_app_port(cpe:CPE))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:mongoPort, exit_no_version:TRUE))
  exit(0);

mongoVer = infos['version'];

if(version_in_range(version:mongoVer, test_version:"6.0", test_version2:"6.11")){
  report = report_fixed_ver(installed_version:mongoVer, fixed_version:"6.12", install_path:infos['location']);
  security_message(data:report, port:mongoPort);
  exit(0);
}

exit(99);