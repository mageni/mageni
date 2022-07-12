###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hp_smh_csrf_vuln.nasl 11872 2018-10-12 11:22:41Z cfischer $
#
# HP System Management Homepage Cross-site Request Forgery Vulnerability
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:hp:system_management_homepage";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805692");
  script_version("$Revision: 11872 $");
  script_cve_id("CVE-2015-2134");
  script_bugtraq_id(75961);
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:22:41 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-07-27 14:14:07 +0530 (Mon, 27 Jul 2015)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("HP System Management Homepage Cross-site Request Forgery Vulnerability");

  script_tag(name:"summary", value:"The host is installed with HP System
  Management Homepage (SMH) and is prone to cross-site request forgery
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to certain actions via
  HTTP requests do not perform any validity checks to verify the requests.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  authenticated users to hijack the authentication of unspecified victims via
  unknown vectors.");

  script_tag(name:"affected", value:"HP System Management Homepage before 7.5.0");

  script_tag(name:"solution", value:"Upgrade to HP System Management Homepage
  7.5.0 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://h20564.www2.hp.com/hpsc/doc/public/display?docId=emr_na-c04746490");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_hp_smh_detect.nasl");
  script_mandatory_keys("HP/SMH/installed");
  script_require_ports("Services/www", 2301, 2381);
  script_xref(name:"URL", value:"http://www8.hp.com/us/en/products/server-software/product-detail.html?oid=344313");
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

if(!smhPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!smhVer = get_app_version(cpe:CPE, port:smhPort)){
  exit(0);
}

if(version_is_less(version:smhVer, test_version:"7.5.0"))
{
  report = 'Installed Version: ' +smhVer+ '\n' +
           'Fixed Version:     '+"7.5.0"+ '\n';
  security_message(data:report, port:smhPort);
  exit(0);
}
