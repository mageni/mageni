###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mantisbt_view_all_bug_page_path_disc_vuln_lin.nasl 12818 2018-12-18 09:55:03Z ckuersteiner $
#
# MantisBT 'view_all_bug_page' Path Disclosure Vulnerability (Linux)
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

CPE = "cpe:/a:mantisbt:mantisbt";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812756");
  script_version("$Revision: 12818 $");
  script_cve_id("CVE-2018-6526");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-12-18 10:55:03 +0100 (Tue, 18 Dec 2018) $");
  script_tag(name:"creation_date", value:"2018-02-05 11:55:27 +0530 (Mon, 05 Feb 2018)");
  script_name("MantisBT 'view_all_bug_page' Path Disclosure Vulnerability (Linux)");

  script_tag(name:"summary", value:"This host is installed with MantisBT and is
  prone to an path disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to insufficient validation
  of user supplied input via 'filter' parameter related to a 'filter_ensure_valid_filter'
  call in 'current_user_api.php' script.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause site path leakage.");

  script_tag(name:"affected", value:"MantisBT version 2.10.0 on Linux");

  script_tag(name:"solution", value:"Upgrade to MantisBT version 2.11.0 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"https://mantisbt.org/bugs/view.php?id=23921");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("mantis_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("mantisbt/detected", "Host/runs_unixoide");
  script_require_ports("Services/www", 80);
  script_xref(name:"URL", value:"http://www.mantisbt.org/download.php");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!manPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!infos = get_app_version_and_location(cpe:CPE, port:manPort, exit_no_version:TRUE)) exit(0);
manVer = infos['version'];
path = infos['location'];

if(manVer == "2.10.0")
{
  report = report_fixed_ver(installed_version: manVer, fixed_version: "2.11.0", install_path:path);
  security_message(port: manPort, data: report);
  exit(0);
}
exit(0);
