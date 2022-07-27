###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_tiv_endpoint_manager_xss_vuln_oct16.nasl 12455 2018-11-21 09:17:27Z cfischer $
#
# IBM Tivoli Endpoint Manager Cross Site Scripting Vulnerability Oct16
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
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

CPE = "cpe:/a:ibm:tivoli_endpoint_manager";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809396");
  script_version("$Revision: 12455 $");
  script_cve_id("CVE-2013-0453");
  script_bugtraq_id(58632);
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-11-21 10:17:27 +0100 (Wed, 21 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-10-24 18:19:22 +0530 (Mon, 24 Oct 2016)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("IBM Tivoli Endpoint Manager Cross Site Scripting Vulnerability Oct16");

  script_tag(name:"summary", value:"This host is installed with IBM Tivoli
  Endpoint Manager and is prone to cross site scripting vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an error in web reports.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to inject arbitrary web script or HTML.");

  script_tag(name:"affected", value:"IBM Tivoli Endpoint Manager versions
  before 8.2.1372.");

  script_tag(name:"solution", value:"Upgrade to IBM Tivoli Endpoint Manager
  version 8.2.1372, or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.ibm.com/blogs/psirt/security-bulletin-cross-site-scripting-xss-vulnerability-was-discovered-in-web-reports-cve-2013-0453/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_ibm_endpoint_manager_web_detect.nasl");
  script_mandatory_keys("ibm_endpoint_manager/installed");
  script_require_ports("Services/www", 52311);
  script_xref(name:"URL", value:"http://www-03.ibm.com/software/products/en/endpoint-manager-family");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!tivPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!tivVer = get_app_version(cpe:CPE, port:tivPort)){
  exit(0);
}

if(version_is_less(version:tivVer, test_version:"8.2.1372"))
{
  report = report_fixed_ver(installed_version:tivVer, fixed_version:"8.2.1372");
  security_message(port:tivPort, data:report);
  exit(0);
}

