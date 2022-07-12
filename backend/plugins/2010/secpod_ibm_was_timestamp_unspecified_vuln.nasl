###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ibm_was_timestamp_unspecified_vuln.nasl 13803 2019-02-21 08:24:24Z cfischer $
#
# IBM WebSphere Application Server WS-Security Policy Unspecified vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.902251");
  script_version("$Revision: 13803 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-21 09:24:24 +0100 (Thu, 21 Feb 2019) $");
  script_tag(name:"creation_date", value:"2010-09-29 09:26:02 +0200 (Wed, 29 Sep 2010)");
  script_cve_id("CVE-2010-3186");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("IBM WebSphere Application Server WS-Security Policy Unspecified vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 SecPod");
  script_family("Web Servers");
  script_dependencies("gb_ibm_websphere_detect.nasl");
  script_mandatory_keys("ibm_websphere_application_server/installed");

  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/2215");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg24027708");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg24027709");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21443736");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Unspecified impact and remote attack vectors.");

  script_tag(name:"affected", value:"IBM WebSphere Application Server (WAS) 7.x before 7.0.0.13.");

  script_tag(name:"insight", value:"The flaw is caused by an unspecified error when using a WS-Security
  enabled JAX-WS web service application while the WS-Security policy specifies 'IncludeTimestamp'.");

  script_tag(name:"summary", value:"The host is running IBM WebSphere Application Server and is prone to
  unspecified vulnerability.");

  script_tag(name:"solution", value:"Apply the fix pack 7.0.0.13 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!vers = get_app_version(cpe:CPE, nofork:TRUE))
  exit(0);

if(version_in_range(version:vers, test_version:"7.0", test_version2:"7.0.0.12")){
  report = report_fixed_ver(installed_version:vers, fixed_version:"7.0.0.12");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);