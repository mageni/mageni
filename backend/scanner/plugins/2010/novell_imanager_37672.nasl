###############################################################################
# OpenVAS Vulnerability Test
# $Id: novell_imanager_37672.nasl 13952 2019-03-01 08:30:06Z ckuersteiner $
#
# Novell iManager Importing/Exporting Schema Stack Buffer Overflow Vulnerability
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100435");
  script_version("$Revision: 13952 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-01 09:30:06 +0100 (Fri, 01 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-01-11 11:18:50 +0100 (Mon, 11 Jan 2010)");
  script_bugtraq_id(37672);
  script_cve_id("CVE-2009-4486");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Novell iManager Importing/Exporting Schema Stack Buffer Overflow Vulnerability");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("novell_imanager_detect.nasl");
  script_require_ports("Services/www", 8080, 8443);
  script_mandatory_keys("novellimanager/installed");

  script_tag(name:"solution", value:"The vendor has released an advisory and fixes. Please see the
references for details.");

  script_tag(name:"summary", value:"Novell iManager is prone to a stack-based buffer-overflow
vulnerability because it fails to perform adequate boundary checks on user-supplied data.

Attackers may exploit this issue to execute arbitrary code in the
context of the affected application. Failed exploit attempts will
likely cause denial-of-service conditions.

Novell iManager 2.7.2 and prior are vulnerable.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37672");
  script_xref(name:"URL", value:"http://www.novell.com/products/consoles/imanager/features.html");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-10-001/");
  script_xref(name:"URL", value:"http://www.novell.com/support/viewContent.do?externalId=7004985&sliceId=1");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

CPE = make_list( "cpe:/a:novell:imanager", "cpe:/a:netiq:imanager" );

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less_equal(version: version, test_version: "2.7.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
