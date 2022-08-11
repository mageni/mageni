###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_atheme_dos_vuln.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# Atheme IRC DoS Vulnerability
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

CPE = "cpe:/a:atheme:atheme";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106634");
  script_version("$Revision: 12106 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-03-07 08:12:26 +0700 (Tue, 07 Mar 2017)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_cve_id("CVE-2017-6384");
  script_bugtraq_id(96552);

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Atheme IRC DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_atheme_detect.nasl");
  script_mandatory_keys("atheme/installed");

  script_tag(name:"summary", value:"Atheme is prone to an denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Memory leak in the login_user function in saslserv/main.c in
saslserv/main.so allows a remote unauthenticated attacker to consume memory and cause a denial of service.");

  script_tag(name:"affected", value:"Atheme version 7.2.7.");

  script_tag(name:"solution", value:"Update to version 7.2.8 or later.");

  script_xref(name:"URL", value:"https://github.com/atheme/atheme/releases/tag/v7.2.8");
  script_xref(name:"URL", value:"https://github.com/atheme/atheme/pull/539");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE))
  exit(0);

if (version == "7.2.7") {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.2.8");
  security_message(port: 0, data: report);
  exit(0);
}

exit(0);
