###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ibm_was_xss_vuln.nasl 13803 2019-02-21 08:24:24Z cfischer $
#
# IBM WebSphere Application Server (WAS) Cross-site Scripting Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902213");
  script_version("$Revision: 13803 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-21 09:24:24 +0100 (Thu, 21 Feb 2019) $");
  script_tag(name:"creation_date", value:"2010-07-02 08:02:13 +0200 (Fri, 02 Jul 2010)");
  script_cve_id("CVE-2010-0778", "CVE-2010-0779");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("IBM WebSphere Application Server (WAS) Cross-site Scripting Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 SecPod");
  script_family("Web Servers");
  script_dependencies("gb_ibm_websphere_detect.nasl");
  script_mandatory_keys("ibm_websphere_application_server/installed");

  script_xref(name:"URL", value:"http://vul.hackerjournals.com/?p=10207");
  script_xref(name:"URL", value:"http://en.securitylab.ru/nvd/395192.php");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/59646");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/59647");
  script_xref(name:"URL", value:"http://www.ibm.com/developerworks/downloads/ws/was/");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Successful exploitation will let attackers to conduct Cross-site scripting
  attacks.");

  script_tag(name:"affected", value:"IBM WAS Version 6.0 before 6.0.2.43, 6.1 before 6.1.0.33 and 7.0 before 7.0.0.11.");

  script_tag(name:"insight", value:"The flaw is due to an error in the Administration Console, which
  allows remote attackers to inject arbitrary web script or HTML via unspecified vectors.");

  script_tag(name:"solution", value:"Upgrade to IBM WAS version 6.0.2.43, 6.1.0.33 or 7.0.0.11.");

  script_tag(name:"summary", value:"The host is running IBM WebSphere Application Server and is prone to Cross-site
  Scripting vulnerability.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!vers = get_app_version(cpe:CPE, nofork:TRUE))
  exit(0);

if(version_in_range(version:vers, test_version:"7.0", test_version2:"7.0.0.10") ||
   version_in_range(version:vers, test_version:"6.0", test_version2:"6.0.2.42") ||
   version_in_range(version:vers, test_version:"6.1", test_version2:"6.1.0.32")){
  report = report_fixed_ver(installed_version:vers, fixed_version:"See advisory");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);