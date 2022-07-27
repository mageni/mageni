###############################################################################
# OpenVAS Vulnerability Test
#
# Nagios Fusion Multiple Cross Site Scripting Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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

CPE = "cpe:/a:nagiosfusion:nagiosfusion";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813252");
  script_version("2019-05-17T10:45:27+0000");
  script_cve_id("CVE-2018-12501");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2018-06-18 15:27:18 +0530 (Mon, 18 Jun 2018)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Nagios Fusion Multiple Cross Site Scripting Vulnerabilities");

  script_tag(name:"summary", value:"This host is running Nagios Fusion and is
  prone to multiple cross site scripting vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple cross site scripting flaws exist
  in an unknown function.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to potentially inject arbitrary html and script code into the web
  site.");

  script_tag(name:"affected", value:"Nagios Fusion versions before 4.1.4");

  script_tag(name:"solution", value:"Upgrade to Nagios Fusion to 4.1.4 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://www.nagios.com");
  script_xref(name:"URL", value:"https://www.nagios.com/downloads/nagios-fusion/change-log");

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_nagios_fusion_detect.nasl");
  script_mandatory_keys("NagiosFusion/installed");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!nesPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!infos = get_app_version_and_location(cpe:CPE, port:nesPort, exit_no_version:TRUE)) exit(0);
nesVer = infos['version'];
path = infos['location'];

if(version_is_less(version:nesVer, test_version:"4.1.4"))
{
  report = report_fixed_ver(installed_version:nesVer, fixed_version:"4.1.4", install_path:path);
  security_message(data:report, port:nesPort);
  exit(0);
}
exit(0);
