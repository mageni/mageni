###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_plone_info_discl_vuln.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# Plone CMS Information Disclosure Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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

CPE = "cpe:/a:plone:plone";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106622");
  script_version("$Revision: 12106 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-02-27 14:16:45 +0700 (Mon, 27 Feb 2017)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2016-4042");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Plone CMS Information Disclosure Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_plone_detect.nasl");
  script_mandatory_keys("plone/installed");

  script_tag(name:"summary", value:"Plone CMS is prone to a information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Plone allows remote attackers to obtain information about the ID of
sensitive content via unspecified vectors.");

  script_tag(name:"impact", value:"An unauthenticated attacker may gain information about private site
content.");

  script_tag(name:"affected", value:"Plone CMS version 3.3.x, 4.x and 5.x");

  script_tag(name:"solution", value:"Apply the hotfix 20160419 or update to version 5.0.5 or later.");

  script_xref(name:"URL", value:"https://plone.org/security/hotfix/20160419/unauthorized-disclosure-of-site-content");
  script_xref(name:"URL", value:"https://plone.org/security/hotfix/20160419");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range(version: version, test_version: "3.3", test_version2: "5.0.4") || version == "5.1a1") {
  report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
