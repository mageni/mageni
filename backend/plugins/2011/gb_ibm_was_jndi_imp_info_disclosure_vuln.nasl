###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_was_jndi_imp_info_disclosure_vuln.nasl 13803 2019-02-21 08:24:24Z cfischer $
#
# IBM WebSphere Application Server JNDI information disclosure Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802400");
  script_version("$Revision: 13803 $");
  script_cve_id("CVE-2009-2747");
  script_bugtraq_id(37355);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2019-02-21 09:24:24 +0100 (Thu, 21 Feb 2019) $");
  script_tag(name:"creation_date", value:"2011-11-04 15:09:13 +0530 (Fri, 04 Nov 2011)");
  script_name("IBM WebSphere Application Server JNDI information disclosure Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_ibm_websphere_detect.nasl");
  script_mandatory_keys("ibm_websphere_application_server/installed");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/54228");
  script_xref(name:"URL", value:"http://www.ibm.com/support/docview.wss?uid=swg1PK99480");
  script_xref(name:"URL", value:"http://www.ibm.com/support/docview.wss?uid=swg1PK91414");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Successful exploitation will let remote unauthorized attackers to access
  or view files or obtain sensitive information.");

  script_tag(name:"affected", value:"IBM WebSphere Application Server (WAS) 6.0 before 6.0.2.39,
  6.1 before 6.1.0.29, and 7.0 before 7.0.0.7.");

  script_tag(name:"insight", value:"The flaw is due to error in the Naming and Directory Interface (JNDI)
  implementation. It does not properly restrict access to UserRegistry object methods, which allows remote
  attackers to obtain sensitive information via a crafted method call.");

  script_tag(name:"summary", value:"The host is running IBM WebSphere Application Server and is prone
  to information disclosure vulnerability.");

  script_tag(name:"solution", value:"For WebSphere Application Server 6.0:

  Apply the latest Fix Pack (6.0.2.39 or later) or APAR PK91414

  For WebSphere Application Server 6.1:

  Apply the latest Fix Pack (6.1.0.29 or later) or APAR PK91414

  For WebSphere Application Server 7.1:

  Apply the latest Fix Pack (7.0.0.7 or later) or APAR PK91414");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

CPE = "cpe:/a:ibm:websphere_application_server";

if(!vers = get_app_version(cpe:CPE, nofork:TRUE))
  exit(0);

if(version_in_range(version:vers, test_version:"7.0", test_version2:"7.0.0.6") ||
   version_in_range(version:vers, test_version:"6.0", test_version2:"6.0.2.38") ||
   version_in_range(version:vers, test_version:"6.1", test_version2:"6.1.0.28")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"See advisory");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);