###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_was_admin_console_info_disclosure_vuln_may17.nasl 13803 2019-02-21 08:24:24Z cfischer $
#
# IBM WAS Administrative Console Information Disclosure Vulnerability
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

CPE = "cpe:/a:ibm:websphere_application_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810979");
  script_version("$Revision: 13803 $");
  script_cve_id("CVE-2017-1137");
  script_bugtraq_id(98419);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2019-02-21 09:24:24 +0100 (Thu, 21 Feb 2019) $");
  script_tag(name:"creation_date", value:"2017-05-22 16:47:45 +0530 (Mon, 22 May 2017)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable"); # we are not able to get the interim fix version...
  script_name("IBM WAS Administrative Console Information Disclosure Vulnerability");

  script_tag(name:"summary", value:"This host is installed with IBM Websphere
  Application Server and is prone to information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists because IBM WebSphere
  Application Server has a potential for weaker than expected security with the
  Administrative Console due to some unspecified error.");

  script_tag(name:"impact", value:"Successful exploitation of this issue may
  allow a remote attacker to obtain sensitive information and gain unauthorized
  access to the admin console.");

  script_tag(name:"affected", value:"IBM WebSphere Application Server versions
  8.5.0.0 through 8.5.5.11, 8.0.0.0 through 8.0.0.13");

  script_tag(name:"solution", value:"Upgrade to IBM WebSphere Application
  Server (WAS) 8.5.5.12 or 8.0.0.14 or later or apply fix pack level available.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21998469");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_ibm_websphere_detect.nasl");
  script_mandatory_keys("ibm_websphere_application_server/installed");

  script_xref(name:"URL", value:"http://www-03.ibm.com/software/products/en/appserv-was");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!appVer = get_app_version(cpe:CPE, nofork:TRUE))
  exit(0);

if( (appVer =~ "^8\.5") && (version_is_less(version:appVer, test_version:'8.5.5.12'))){
  fix = "8.5.5.12";
}
else if( (appVer =~ "^8\.0") && (version_is_less(version:appVer, test_version:'8.0.0.14'))){
  fix = "8.0.0.14";
}

if(fix) {
  report = report_fixed_ver(installed_version:appVer, fixed_version:fix);
  security_message(port:0, data:report);
  exit( 0 );
}

exit(99);