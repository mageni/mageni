###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_websphere_portal_xss_vuln_swg22000152.nasl 14175 2019-03-14 11:27:57Z cfischer $
#
# IBM WebSphere Portal Cross Site Scripting Vulnerability(swg22000152)
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
  script_oid("1.3.6.1.4.1.25623.1.0.810732");
  script_version("$Revision: 14175 $");
  script_cve_id("CVE-2017-1120");
  script_bugtraq_id(97075);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2019-03-14 12:27:57 +0100 (Thu, 14 Mar 2019) $");
  script_tag(name:"creation_date", value:"2017-04-07 16:26:30 +0530 (Fri, 07 Apr 2017)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("IBM WebSphere Portal Cross Site Scripting Vulnerability(swg22000152)");

  script_tag(name:"summary", value:"This host is installed with IBM Websphere
  Portal and is prone to cross site scripting vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to error in handling embed
  arbitrary JavaScript code in the Web UI thus altering the intended functionality
  potentially leading to credentials disclosure within a trusted session.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote
  attacker to execute arbitrary script code in the browser of an unsuspecting
  user in the context of the affected site. This may allow the attacker to
  steal cookie-based authentication credentials and launch other attacks.");

  script_tag(name:"affected", value:"IBM WebSphere Portal 8.5.0 before Cumulative Fix 14 (CF14)
  IBM WebSphere Portal 9.0.0 before Cumulative Fix 14 (CF14)");

  script_tag(name:"solution", value:"Upgrade to IBM WebSphere Portal
  8.5.0 with Cumulative Fix 14 (CF14), 9.0.0 with Cumulative Fix 14 (CF14) or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg22000152");
  script_xref(name:"URL", value:"https://exchange.xforce.ibmcloud.com/vulnerabilities/121172");
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
  if(version_is_less(version:webVer, test_version:"8.5.0.0.14"))
  {
    fix = "8.5.0.0 CF14";
    VULN = TRUE;
  }
}

else if(webVer =~ "^9\.0\.0")
{
  if(version_is_less(version:webVer, test_version:"9.0.0.0.14"))
  {
    fix = "9.0.0.0 CF14";
    VULN = TRUE;
  }
}

if(VULN)
{
  report = report_fixed_ver(installed_version:webVer, fixed_version:fix);
  security_message(data:report, port:webPort);
  exit(0);
}

