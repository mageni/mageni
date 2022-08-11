###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ocs_inventory_ng_rem_sh_upl_vuln.nasl 13699 2019-02-15 14:29:50Z cfischer $
#
# OCS Inventory NG <= 2.5.0 Remote Shell Upload Vulnerability
#
# Authors:
# Michael Martin <michael.martin@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH
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

CPE = "cpe:/a:ocsinventory-ng:ocs_inventory_ng";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107374");
  script_version("$Revision: 13699 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-15 15:29:50 +0100 (Fri, 15 Feb 2019) $");
  script_tag(name:"creation_date", value:"2018-11-23 11:45:49 +0100 (Fri, 23 Nov 2018)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_cve_id("CVE-2018-15537");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_name("OCS Inventory NG <= 2.5.0 Remote Shell Upload Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_ocs_inventory_ng_detect.nasl");
  script_mandatory_keys("ocs_inventory_ng/detected");

  script_tag(name:"summary", value:"OCS Inventory NG <= 2.5.0 is prone to a remote shell upload vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"OCS Inventory NG could allow a remote authenticated attacker to upload arbitrary files. By sending a specially-crafted HTTP request, a remote attacker could exploit this vulnerability to upload a malicious PHP script, which could allow the attacker to execute arbitrary PHP code on the vulnerable system.");

  script_tag(name:"impact", value:"Remotely authenticated attackers might use this vulnerability to execute arbitrary code on the target.");

  script_tag(name:"affected", value:"OCS Inventory NG version <= 2.5.0");

  script_tag(name:"solution", value:"No known solution is available as of 12th February, 2019.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://seclists.org/fulldisclosure/2018/Nov/40");
  script_xref(name:"URL", value:"https://exchange.xforce.ibmcloud.com/vulnerabilities/152967");
  script_xref(name:"URL", value:"https://github.com/OCSInventory-NG/OCSInventory-ocsreports/releases");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less_equal(version: version, test_version: "2.5.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "None");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
