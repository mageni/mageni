###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_websphere_privilege_escalation_vuln_mar16.nasl 13803 2019-02-21 08:24:24Z cfischer $
#
# IBM Websphere Application Server Privilege Escalation Vulnerability Mar16
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
  script_oid("1.3.6.1.4.1.25623.1.0.806891");
  script_version("$Revision: 13803 $");
  script_cve_id("CVE-2014-8890");
  script_bugtraq_id(71834);
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2019-02-21 09:24:24 +0100 (Thu, 21 Feb 2019) $");
  script_tag(name:"creation_date", value:"2016-03-03 18:23:42 +0530 (Thu, 03 Mar 2016)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("IBM Websphere Application Server Privilege Escalation Vulnerability Mar16");

  script_tag(name:"summary", value:"This host is installed with IBM Websphere
  application server and is prone to privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw will occur when the deployment
  descriptor security constraints are combined with ServletSecurity annotations
  on a servlet.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to gain elevated privileges on the system.");

  script_tag(name:"affected", value:"IBM WebSphere Application Server (WAS)
  Liberty Profile 8.5.x before 8.5.5.4.");

  script_tag(name:"solution", value:"Upgrade to IBM WebSphere Application
  Server (WAS) version 8.5.5.4, or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21690185");

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

if(version_in_range(version:wasVer, test_version:"8.5", test_version2:"8.5.5.3"))
{
  report = report_fixed_ver(installed_version:wasVer, fixed_version:"8.5.5.4");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);