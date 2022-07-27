###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_websphere_session_hijack_vuln_apr16.nasl 13803 2019-02-21 08:24:24Z cfischer $
#
# IBM Websphere Application Server Session Hijack Vulnerability Apr16
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.807651");
  script_version("$Revision: 13803 $");
  script_cve_id("CVE-2015-1936");
  script_bugtraq_id(75480);
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2019-02-21 09:24:24 +0100 (Thu, 21 Feb 2019) $");
  script_tag(name:"creation_date", value:"2016-04-12 18:40:51 +0530 (Tue, 12 Apr 2016)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("IBM Websphere Application Server Session Hijack Vulnerability Apr16");

  script_tag(name:"summary", value:"This host is installed with IBM Websphere
  application server and is prone to session hijack vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an error in
  administrative console.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to hijack a user's session on the system.");

  script_tag(name:"affected", value:"IBM WebSphere Application Server (WAS)
  8.0.0 before 8.0.0.12 and 8.5 before 8.5.5.6");

  script_tag(name:"solution", value:"Upgrade to IBM WebSphere Application
  Server (WAS) 8.0.0.12, 8.5.5.6 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21959083");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_ibm_websphere_detect.nasl");
  script_mandatory_keys("ibm_websphere_application_server/installed");

  script_xref(name:"URL", value:"http://www-03.ibm.com/software/products/en/appserv-was");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!wasVer = get_app_version(cpe:CPE, nofork:TRUE))
  exit(0);

if(version_in_range(version:wasVer, test_version:"8.5", test_version2:"8.5.5.5"))
{
  fix = "8.5.5.6";
  VULN = TRUE;
}

else if(version_in_range(version:wasVer, test_version:"8.0", test_version2:"8.0.0.11"))
{
  fix = "8.0.0.12";
  VULN = TRUE;
}

if(VULN)
{
  report = report_fixed_ver(installed_version:wasVer, fixed_version:fix);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);