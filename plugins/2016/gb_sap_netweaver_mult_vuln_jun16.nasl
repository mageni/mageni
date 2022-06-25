###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sap_netweaver_mult_vuln_jun16.nasl 14181 2019-03-14 12:59:41Z cfischer $
#
# SAP NetWeaver Multiple Vulnerabilities
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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

CPE = 'cpe:/a:sap:netweaver';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106104");
  script_version("$Revision: 14181 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-14 13:59:41 +0100 (Thu, 14 Mar 2019) $");
  script_tag(name:"creation_date", value:"2016-06-21 15:14:09 +0700 (Tue, 21 Jun 2016)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2016-3974", "CVE-2016-3975", "CVE-2016-3976");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("SAP NetWeaver Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_sap_netweaver_detect.nasl");
  script_mandatory_keys("sap_netweaver/installed");

  script_tag(name:"summary", value:"SAP NetWeaver is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"SAP NetWeaver contains multiple vulnerabilities:

An XML external entity (XXE) vulnerability in the Configuration Wizard allows remote attackers to cause a
denial of service, conduct SMB Relay attacks, or access arbitrary files via a crafted XML request related
to the ctcprotocol servlet. (CVE-2016-3974)

Anonymous attacker can use a XSS vulnerability to hijack session data of administrators or users of a web
resource. (CVE-2016-3975)

An authorized attacker can use a directory traversal attack to read files from the server and then escalate
his or her privileges. (CVE-2016-3976)");

  script_tag(name:"impact", value:"A remote attacker may cause a denial of service, access arbitrary files
or hijack user sessions. An authenticated remote attacker may read arbitrary files leading to privilege
escalation.");

  script_tag(name:"affected", value:"Version 7.1 - 7.5");

  script_tag(name:"solution", value:"Check the references for solutions.");

  script_xref(name:"URL", value:"https://service.sap.com/sap/support/notes/2235994");
  script_xref(name:"URL", value:"https://service.sap.com/sap/support/notes/2234971");
  script_xref(name:"URL", value:"https://service.sap.com/sap/support/notes/2238375");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range(version: version, test_version: "7.10", test_version2: "7.50")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "See advisory.");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
