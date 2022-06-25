###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_was_remote_privilege_escalation_vul.nasl 13803 2019-02-21 08:24:24Z cfischer $
#
# IBM Websphere Application Server Remote Privilege Escalation Vulnerability
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.811442");
  script_version("$Revision: 13803 $");
  script_cve_id("CVE-2017-1151");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2019-02-21 09:24:24 +0100 (Thu, 21 Feb 2019) $");
  script_tag(name:"creation_date", value:"2017-08-04 11:32:43 +0530 (Fri, 04 Aug 2017)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  ## Qod Reduced, IBM WAS should be configured with OpenID Connect (OIDC) Trust Association Interceptor (TAI)
  script_name("IBM Websphere Application Server Remote Privilege Escalation Vulnerability");

  script_tag(name:"summary", value:"This host is installed with IBM Websphere
  application server and is prone to remote privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to a potential privilege
  escalation vulnerability in WebSphere Application Server traditional when using
  the OpenID Connect (OIDC) Trust Association Interceptor (TAI).");

  script_tag(name:"impact", value:"Successful exploitation will allow a user to
  gain elevated privileges on the system.");

  script_tag(name:"affected", value:"IBM WebSphere Application Server (WAS)
  V9.0.0.0 through 9.0.0.3, V8.5.5.3 through 8.5.5.11, V8.0.0.10 through 8.0.0.13");

  script_tag(name:"solution", value:"Upgrade to IBM WebSphere Application
  Server (WAS) 9.0.0.4 or 8.5.5.12 or 8.0.0.14 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21999293");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_ibm_websphere_detect.nasl");
  script_mandatory_keys("ibm_websphere_application_server/installed");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!wasVer = get_app_version(cpe:CPE, nofork:TRUE))
  exit(0);

if(wasVer =~ "^[89]")
{
  if(wasVer =~ "^8\.0\.0\.1")
  {
    if(version_in_range(version:wasVer, test_version:"8.0.0.10", test_version2:"8.0.0.13")){
      fix = "8.0.0.14";
    }
  }
  else if(wasVer =~ "^8\.5\.5")
  {
    if(version_in_range(version:wasVer, test_version:"8.5.5.3", test_version2:"8.5.5.11")){
      fix = "8.5.5.12";
    }
  }
  else if(wasVer =~ "^9\.0\.0")
  {
    if(version_in_range(version:wasVer, test_version:"9.0.0.0", test_version2:"9.0.0.3")){
      fix = "9.0.0.4";
    }
  }

  if(fix)
  {
    report = report_fixed_ver(installed_version:wasVer, fixed_version:fix);
    security_message(port:0, data:report);
    exit(0);
  }
}

exit(99);