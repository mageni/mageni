###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_horde_gollem_module_unauthorized_file_download_vuln_win.nasl 12986 2019-01-09 07:58:52Z cfischer $
#
# Horde Gollem Module Unauthorized File Download Vulnerability (Windows)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:horde:horde_groupware";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812234");
  script_version("$Revision: 12986 $");
  script_cve_id("CVE-2017-15235");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2019-01-09 08:58:52 +0100 (Wed, 09 Jan 2019) $");
  script_tag(name:"creation_date", value:"2017-12-06 18:23:41 +0530 (Wed, 06 Dec 2017)");
  script_name("Horde Gollem Module Unauthorized File Download Vulnerability (Windows)");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("horde_detect.nasl", "gb_horde_gollem_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("horde/installed", "horde/gollem/installed", "Host/runs_windows");

  script_xref(name:"URL", value:"https://blogs.securiteam.com/index.php/archives/3454");

  script_tag(name:"summary", value:"This host is running Horde Groupware and is
  prone to an unauthorized file download vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to user controlled input is
  not sufficiently sanitized when passed to File Manager (gollem) module.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to bypass Horde authentication for file downloads via a crafted
  'fn' parameter that corresponds to the exact filename.");

  script_tag(name:"affected", value:"The File Manager (gollem) module 3.0.11 in
  Horde Groupware 5.2.21 on Windows.");

  script_tag(name:"solution", value:"Upgrade to latest version of Horde Groupware
  and File Manager (gollem) module.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

hordeVer = infos['version'];
hordePath = infos['location'];

if(hordeVer == "5.2.21") {

  if(!infos = get_app_version_and_location(cpe:"cpe:/a:horde:gollem", port:port, exit_no_version:TRUE))
    exit(0);

  gollemVer = infos['version'];
  gollemPath = infos['location'];

  if(gollemVer == "3.0.11") {
    report = report_fixed_ver(installed_version:"Horde Groupware " + hordeVer + " with Gollem version " + gollemVer,
                              fixed_version:"Upgrade to latest version", install_path:"Horde Groupware: " + hordePath + " Gollem: " + gollemPath);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);