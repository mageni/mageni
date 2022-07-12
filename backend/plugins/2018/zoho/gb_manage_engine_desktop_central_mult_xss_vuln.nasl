###############################################################################
# OpenVAS Vulnerability Test
#
# ZOHO ManageEngine Desktop Central Multiple Cross Site Scripting Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH http://www.greenbone.net
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
###############################################################################

CPE = "cpe:/a:zohocorp:manageengine_desktop_central";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812576");
  script_version("2019-05-17T10:45:27+0000");
  script_cve_id("CVE-2018-8722");
  script_bugtraq_id(103426);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2018-03-21 10:15:02 +0530 (Wed, 21 Mar 2018)");
  script_name("ZOHO ManageEngine Desktop Central Multiple Cross Site Scripting Vulnerabilities");

  script_tag(name:"summary", value:"This host is installed with ManageEngine
  Desktop Central and is prone to multiple cross site scripting vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw allows to inject client-side script
  into Desktop Centrals web page.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  to execute arbitrary script code in the browser of an unsuspecting user in
  the context of the affected site. This may allow the attacker to steal
  cookie-based authentication credentials and to launch other attacks.");

  script_tag(name:"affected", value:"Zoho ManageEngine Desktop Central version 9.1.0 build 91099");

  script_tag(name:"solution", value:"Upgrade to ManageEngine Desktop Central build
  version 92026 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");
  script_xref(name:"URL", value:"https://www.manageengine.com/products/desktop-central/cross-site-scripting-vulnerability.html");

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_manage_engine_desktop_central_detect.nasl");
  script_mandatory_keys("ManageEngine/Desktop_Central/installed");
  script_require_ports("Services/www", 8040);
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!mePort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!infos = get_app_version_and_location(cpe:CPE, port:mePort, exit_no_version:TRUE )) exit(0);
vers = infos['version'];
path = infos['location'];

if(version_is_equal(version:vers, test_version:"91099"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"Upgrade to build 92026", install_path:path);
  security_message(port:mePort, data:report);
  exit(0);
}
