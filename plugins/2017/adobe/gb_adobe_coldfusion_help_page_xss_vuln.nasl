###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_coldfusion_help_page_xss_vuln.nasl 12142 2018-10-29 08:28:54Z cfischer $
#
# Adobe ColdFusion Help Page Cross Site Scripting Vulnerability
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

CPE = "cpe:/a:adobe:coldfusion";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812286");
  script_version("$Revision: 12142 $");
  script_cve_id("CVE-2014-5315");
  script_bugtraq_id(69791);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-29 09:28:54 +0100 (Mon, 29 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-12-29 11:29:42 +0530 (Fri, 29 Dec 2017)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Adobe ColdFusion Help Page Cross Site Scripting Vulnerability");

  script_tag(name:"summary", value:"This host is running Adobe ColdFusion and is
  prone to cross site scripting vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an input validation
  error in Help page.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to inject arbitrary web script or HTML via unspecified vectors.");

  script_tag(name:"affected", value:"ColdFusion 8.0.1 and earlier.");

  script_tag(name:"solution", value:"Upgrade to ColdFusion 9 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://jvn.jp/en/jp/JVN84376800/index.html");
  script_xref(name:"URL", value:"http://jvndb.jvn.jp/en/contents/2014/JVNDB-2014-000105.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_coldfusion_detect.nasl");
  script_mandatory_keys("coldfusion/installed");
  script_require_ports("Services/www", 80);
  script_xref(name:"URL", value:"http://www.adobe.com");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!cfPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!infos = get_app_version_and_location( cpe:CPE, port:cfPort, exit_no_version:TRUE)) exit(0);
cfdVer = infos['version'];
path = infos['location'];

#https://it.wikipedia.org/wiki/Adobe_ColdFusion
if(version_is_less(version:cfdVer, test_version:"9.0"))
{
  report = report_fixed_ver(installed_version:cfdVer, fixed_version:"Upgrade to ColdFusion 9 or later", install_path:path);
  security_message(data:report, port:cfPort);
  exit(0);
}
exit(0);
