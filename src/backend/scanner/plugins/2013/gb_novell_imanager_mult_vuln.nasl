###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_novell_imanager_mult_vuln.nasl 13952 2019-03-01 08:30:06Z ckuersteiner $
#
# Novell iManager Multiple Vulnerabilities
#
# Authors:
# Arun Kallavi <karun@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_tag(name:"impact", value:"Successful exploitation may allow remote attackers to perform unauthorized
  actions and gain access to the affected application. Other attacks are also possible.");

  script_tag(name:"affected", value:"Novell iManager version prior to 2.7 SP 6 patch 1");

  script_tag(name:"insight", value:"Multiple flaws due to,

  - Does not refresh a token after a logout action.

  - Does not require multiple steps or explicit confirmation for sensitive
    transactions.");

  script_tag(name:"summary", value:"The host is running Novell iManager and is prone to multiple unspecified
  vulnerabilities.");

  script_tag(name:"solution", value:"Apply the patch.");

  script_oid("1.3.6.1.4.1.25623.1.0.803626");
  script_version("$Revision: 13952 $");
  script_cve_id("CVE-2013-3268", "CVE-2013-1088");
  script_bugtraq_id(59042, 59450);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2019-03-01 09:30:06 +0100 (Fri, 01 Mar 2019) $");
  script_tag(name:"creation_date", value:"2013-06-04 16:30:14 +0530 (Tue, 04 Jun 2013)");

  script_name("Novell iManager Multiple Vulnerabilities");

  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_family("General");
  script_dependencies("novell_imanager_detect.nasl");
  script_mandatory_keys("novellimanager/installed");
  script_require_ports("Services/www", 8080, 8443);

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.novell.com/support/kb/doc.php?id=7010166");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

CPE = make_list( "cpe:/a:novell:imanager", "cpe:/a:netiq:imanager" );

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version:"2.7.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.7 SP 6 patch 1");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
