##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_foreman_info_discl_vuln1.nasl 14107 2019-03-12 07:31:46Z cfischer $
#
# Foreman Information Disclosure Vulnerability-01
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

CPE = 'cpe:/a:theforeman:foreman';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106419");
  script_version("$Revision: 14107 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-12 08:31:46 +0100 (Tue, 12 Mar 2019) $");
  script_tag(name:"creation_date", value:"2016-11-29 08:20:28 +0700 (Tue, 29 Nov 2016)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:N/A:N");

  script_cve_id("CVE-2016-5390");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Foreman Information Disclosure Vulnerability-01");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_foreman_detect.nasl");
  script_mandatory_keys("foreman/installed");

  script_tag(name:"summary", value:"Foreman is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Non-admin users with the view_hosts permission containing a filter are
able to access API routes beneath 'hosts' such as GET /api/v2/hosts/secrethost/interfaces without the filter
being taken into account. This allows users to access network interface details (including BMC login details)
for any host.");

  script_tag(name:"affected", value:"Version 1.10.0 to 1.12.0, except 1.11.4");

  script_tag(name:"solution", value:"Upgrade to 1.11.4, 1.12.1 or later.");

  script_xref(name:"URL", value:"https://theforeman.org/security.html#2016-5390");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range(version: version, test_version: "1.10.0", test_version2: "1.12.0")) {
  if (version != "1.11.4") {
    report = report_fixed_ver(installed_version: version, fixed_version: "1.12.1");
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(0);
