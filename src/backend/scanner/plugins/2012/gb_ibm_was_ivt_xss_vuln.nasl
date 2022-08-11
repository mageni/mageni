###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_was_ivt_xss_vuln.nasl 13803 2019-02-21 08:24:24Z cfischer $
#
# IBM WebSphere Application Server IVT Cross Site Scripting Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802413");
  script_version("$Revision: 13803 $");
  script_cve_id("CVE-2011-1362");
  script_bugtraq_id(46736);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2019-02-21 09:24:24 +0100 (Thu, 21 Feb 2019) $");
  script_tag(name:"creation_date", value:"2012-01-18 18:06:52 +0530 (Wed, 18 Jan 2012)");
  script_name("IBM WebSphere Application Server IVT Cross Site Scripting Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_ibm_websphere_detect.nasl");
  script_mandatory_keys("ibm_websphere_application_server/installed");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/69731");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg27007951");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1PM43792");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?rs=180&uid=swg24031034");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Successful exploitation will let attackers to conduct cross-site scripting
  attacks.");

  script_tag(name:"affected", value:"IBM WebSphere Application Server (WAS) version 6.1 before 6.1.0.41

  IBM WebSphere Application Server (WAS) version 7.0 before 7.0.0.19.");

  script_tag(name:"insight", value:"The flaw is due to an error in Installation Verification Test (IVT)
  application in the Install component, which allows remote attackers to inject
  arbitrary web script or HTML via unspecified vectors.");

  script_tag(name:"solution", value:"Upgrade to version 6.1.0.41 or 7.0.0.19 or later.");

  script_tag(name:"summary", value:"The host is running IBM WebSphere Application Server and is prone to cross site
  scripting vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

CPE = "cpe:/a:ibm:websphere_application_server";

if(!vers = get_app_version(cpe:CPE, nofork:TRUE))
  exit(0);

if(version_in_range(version:vers, test_version:"6.1", test_version2:"6.1.0.40")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"6.1.0.41");
  security_message(port:0, data:report);
  exit(0);
}

if(version_in_range(version:vers, test_version:"7.0", test_version2:"7.0.0.18")){
  report = report_fixed_ver(installed_version:vers, fixed_version:"7.0.0.19");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);