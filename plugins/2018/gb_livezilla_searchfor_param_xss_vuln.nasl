###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_livezilla_searchfor_param_xss_vuln.nasl 8845 2018-02-16 10:57:50Z santu $
#
# LiveZilla 'knowledgebase.php' Cross Site Scripting Vulnerability 
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

CPE = "cpe:/a:livezilla:livezilla";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812760");
  script_version("$Revision: 8845 $");
  script_cve_id("CVE-2017-15869");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-02-16 11:57:50 +0100 (Fri, 16 Feb 2018) $");
  script_tag(name:"creation_date", value:"2018-02-12 13:29:54 +0530 (Mon, 12 Feb 2018)");
  script_name("LiveZilla 'knowledgebase.php' Cross Site Scripting Vulnerability");

  script_tag(name:"summary", value:"This host is installed with LiveZilla and is
  prone to cross site scripting vulnerability.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help of
  detect NVT and check the version is vulnerable or not.");

  script_tag(name:"insight", value:"The flaw is due to an insufficient validation
  of user supplied input via 'search-for' parameter in 'knowledgebase.php' script.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to inject arbitrary web script or HTML via the search-for parameter.

  Impact Level: Application");

  script_tag(name:"affected", value:"LiveZilla versions 7.0.6.0");

  script_tag(name:"solution", value:"Upgrade to version 7.0.8.9 or later,
  For updates refer to https://www.livezilla.net");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");
  script_xref(name:"URL", value:"https://www.securityfocus.com/archive/1/archive/1/541688/100/0/threaded");
  script_xref(name:"URL", value:"https://www.pallas.com/advisories/cve-2017-15869-livezilla-xss-knowledgebase");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_livezilla_detect.nasl");
  script_mandatory_keys("LiveZilla/installed");
  script_require_ports("Services/www", 80);
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

livPort = "";
livVer = "";

if(!livPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!infos = get_app_version_and_location(cpe:CPE, port:livPort, exit_no_version:TRUE)) exit(0);
livVer = infos['version'];
path = infos['location'];

if(livVer == "7.0.6.0")
{
  report = report_fixed_ver(installed_version: livVer, fixed_version: "7.0.8.9 or later", install_path:path);
  security_message(port: livPort, data: report);
  exit(0);
}
exit(0);
