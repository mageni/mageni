###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_websphere_39701.nasl 13803 2019-02-21 08:24:24Z cfischer $
#
# IBM WebSphere Application Server SIP Logging Information Disclosure Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Uodated By: Antu sanadi <santu@secpod.com> on 2010-05-11
#  - Added the related CVE's
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

CPE = "cpe:/a:ibm:websphere_application_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100609");
  script_version("$Revision: 13803 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-21 09:24:24 +0100 (Thu, 21 Feb 2019) $");
  script_tag(name:"creation_date", value:"2010-04-28 14:05:27 +0200 (Wed, 28 Apr 2010)");
  script_cve_id("CVE-2010-1650", "CVE-2010-1651");
  script_bugtraq_id(39701);
  script_name("IBM WebSphere Application Server SIP Logging Information Disclosure Vulnerability");
  script_tag(name:"cvss_base", value:"1.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:N/A:N");
  script_category(ACT_GATHER_INFO);
  script_family("Web Servers");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("gb_ibm_websphere_detect.nasl");
  script_mandatory_keys("ibm_websphere_application_server/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/39701");
  script_xref(name:"URL", value:"http://www-306.ibm.com/software/websphere/#");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"Updates are available. Please see the references for details.");

  script_tag(name:"summary", value:"IBM WebSphere Application Server (WAS) is prone to an information-
  disclosure vulnerability.");

  script_tag(name:"impact", value:"A local authenticated attacker can exploit this issue to gain access
  to sensitive information. This may aid in further attacks.");

  script_tag(name:"affected", value:"Versions prior to WAS 7.0.0.11 and 6.1.0.31 are vulnerable.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!vers = get_app_version(cpe:CPE, nofork:TRUE))
  exit(0);

if(version_in_range(version:vers, test_version:"7", test_version2:"7.0.0.10") ||
   version_in_range(version:vers, test_version:"6.1", test_version2:"6.1.0.30")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"7.0.0.11/6.1.0.31");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);