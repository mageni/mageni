###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_websphere_mult_vuln.nasl 13803 2019-02-21 08:24:24Z cfischer $
#
# IBM WebSphere Application Server multiple vulnerabilities.
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100565");
  script_version("$Revision: 13803 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-21 09:24:24 +0100 (Thu, 21 Feb 2019) $");
  script_tag(name:"creation_date", value:"2010-04-01 13:43:26 +0200 (Thu, 01 Apr 2010)");
  script_bugtraq_id(39051, 39056);
  script_cve_id("CVE-2010-0768", "CVE-2010-0770", "CVE-2010-0769");
  script_name("IBM WebSphere Application Server multiple vulnerabilities");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_category(ACT_GATHER_INFO);
  script_family("Web Servers");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("gb_ibm_websphere_detect.nasl");
  script_mandatory_keys("ibm_websphere_application_server/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/39051");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/39056");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?rs=180&uid=swg27004980");
  script_xref(name:"URL", value:"http://www-306.ibm.com/software/websphere/#");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/57164");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/57182");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for
  details.");

  script_tag(name:"summary", value:"IBM WebSphere Application Server (WAS) is prone to multiple
  vulnerabilities.");

  script_tag(name:"insight", value:"1. A cross-site scripting vulnerability because the application
  fails to properly sanitize user-supplied input.

  An attacker may leverage this issue to execute arbitrary script code
  in the browser of an unsuspecting user in the context of the affected
  site. This may let the attacker steal cookie-based authentication
  credentials and launch other attacks.

  2. A Remote Denial Of Service Vulnerability.

  Exploiting this issue allows remote attackers to cause WAS ORB threads
  to hang, denying service to legitimate users.");

  script_tag(name:"affected", value:"Versions prior to WAS 7.0.0.9, 6.1.0.31, and 6.0.2.4 are vulnerable.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

CPE = "cpe:/a:ibm:websphere_application_server";

if(!vers = get_app_version(cpe:CPE, nofork:TRUE))
  exit(0);

if(version_in_range(version:vers, test_version:"7",   test_version2:"7.0.0.8")   ||
   version_in_range(version:vers, test_version:"6.1", test_version2:"6.1.0.30")  ||
   version_in_range(version:vers, test_version:"6.0", test_version2:"6.0.2.40")) {
   report = report_fixed_ver(installed_version:vers, fixed_version:"See advisory");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);