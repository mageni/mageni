###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_websphere_security_bypass_vuln_jan16.nasl 13803 2019-02-21 08:24:24Z cfischer $
#
# IBM Websphere Application Server Security Bypass Vulnerability Jan16
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
  script_oid("1.3.6.1.4.1.25623.1.0.806844");
  script_version("$Revision: 13803 $");
  script_cve_id("CVE-2013-0462");
  script_bugtraq_id(57513);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2019-02-21 09:24:24 +0100 (Thu, 21 Feb 2019) $");
  script_tag(name:"creation_date", value:"2016-01-20 17:51:20 +0530 (Wed, 20 Jan 2016)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("IBM Websphere Application Server Security Bypass Vulnerability Jan16");

  script_tag(name:"summary", value:"This host is installed with IBM Websphere
  application server and is prone to security bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an unspecified
  vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  a remote attacker to bypass certain security restrictions, which may aid in
  further attacks.");

  script_tag(name:"affected", value:"IBM WebSphere Application Server (WAS)
  6.1, 7.0 before 7.0.0.27, 8.0, and 8.5");

  script_tag(name:"solution", value:"Apply the patch from below link.");

  script_tag(name:"solution_type", value:"Workaround");

  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21632423");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_ibm_websphere_detect.nasl");
  script_mandatory_keys("ibm_websphere_application_server/installed");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!wasVer = get_app_version(cpe:CPE, nofork:TRUE))
  exit(0);

if(version_is_equal(version:wasVer, test_version:"6.1") ||
   version_in_range(version:wasVer, test_version:"7.0", test_version2:"7.0.0.27") ||
   version_is_equal(version:wasVer, test_version:"8.0") ||
   version_is_equal(version:wasVer, test_version:"8.5"))
{
  report = report_fixed_ver(installed_version:wasVer, fixed_version: "Apply the patch");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);