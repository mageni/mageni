###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_websphere_portal_access_ctl_bypass_vuln_swg21968474.nasl 14175 2019-03-14 11:27:57Z cfischer $
#
# IBM WebSphere Portal Access Control Bypass Vulnerability(swg22000152)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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

CPE = 'cpe:/a:ibm:websphere_portal';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810733");
  script_version("$Revision: 14175 $");
  script_cve_id("CVE-2015-4997");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2019-03-14 12:27:57 +0100 (Thu, 14 Mar 2019) $");
  script_tag(name:"creation_date", value:"2017-04-07 17:09:57 +0530 (Fri, 07 Apr 2017)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("IBM WebSphere Portal Access Control Bypass Vulnerability(swg22000152)");

  script_tag(name:"summary", value:"This host is installed with IBM Websphere
  Portal and is prone to access control bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an improper validation
  of access control. By sending specially crafted requests, an attacker could
  exploit this vulnerability to bypass security and gain unauthorized access
  to the vulnerable system or other systems.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote
  attacker to bypass access control restrictions and gain access to the target
  system.");

  script_tag(name:"affected", value:"IBM WebSphere Portal 8.5.0 before Cumulative Fix 08 (CF08)");

  script_tag(name:"solution", value:"Upgrade to IBM WebSphere Portal
  8.5.0 with Cumulative Fix 08 (CF08) later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21968474");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1033982");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1PI47694");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_ibm_websphere_portal_detect.nasl");
  script_mandatory_keys("ibm_websphere_portal/installed");
  script_xref(name:"URL", value:"https://www.ibm.com/developerworks/downloads/ls/wpe");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!webPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!webVer = get_app_version(cpe:CPE, port:webPort)){
 exit(0);
}

if(webVer =~ "^8\.5\.0")
{
  if(version_is_less(version:webVer, test_version:"8.5.0.0.8"))
  {
    report = report_fixed_ver(installed_version:webVer, fixed_version:"8.5.0 Cumulative Fix 08 (CF08) or later");
    security_message(data:report, port:webPort);
    exit(0);
  }
}
