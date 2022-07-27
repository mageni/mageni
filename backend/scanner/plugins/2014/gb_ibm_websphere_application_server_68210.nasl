###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_websphere_application_server_68210.nasl 13803 2019-02-21 08:24:24Z cfischer $
#
# IBM WebSphere Application Server Unspecified Information Disclosure Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2014 Greenbone Networks GmbH
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

CPE = "cpe:/a:ibm:websphere_application_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105071");
  script_bugtraq_id(68210, 68211);
  script_cve_id("CVE-2014-0965", "CVE-2014-3022");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_version("$Revision: 13803 $");
  script_name("IBM WebSphere Application Server Unspecified Information Disclosure Vulnerability");
  script_tag(name:"last_modification", value:"$Date: 2019-02-21 09:24:24 +0100 (Thu, 21 Feb 2019) $");
  script_tag(name:"creation_date", value:"2014-08-21 11:58:12 +0200 (Thu, 21 Aug 2014)");
  script_category(ACT_GATHER_INFO);
  script_family("Web Servers");
  script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("gb_ibm_websphere_detect.nasl");
  script_mandatory_keys("ibm_websphere_application_server/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/68210");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/68211");
  script_xref(name:"URL", value:"http://www.ibm.com");
  script_xref(name:"URL", value:"http://www-4.ibm.com/software/webservers/appserv/");

  script_tag(name:"impact", value:"Attackers can exploit this issue to obtain sensitive information that
  may lead to further attacks.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"Updates are available.");

  script_tag(name:"summary", value:"The IBM WebSphere Application Server is prone to an unspecified remote
  information-disclosure vulnerability because of improper handling of SOAP responses.");

  script_tag(name:"affected", value:"IBM WebSphere Application Server 8.5.0.0 through 8.5.5.1

  IBM WebSphere Application Server 8.0.0.0 through 8.0.0.8

  IBM WebSphere Application Server 7.0.0.0 through 7.0.0.31");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!vers = get_app_version(cpe:CPE, nofork:TRUE))
  exit(0);

if(version_in_range(version:vers, test_version:"8.5", test_version2:"8.5.5.1") ||
   version_in_range(version:vers, test_version:"8.0", test_version2:"8.0.0.8") ||
   version_in_range(version:vers, test_version:"7.0", test_version2:"7.0.0.29")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"See advisory");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);