###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_asterisk_dos_vuln1.nasl 13267 2019-01-24 12:56:48Z cfischer $
#
# Asterisk 'CVE-2017-14098' DoS Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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

CPE = 'cpe:/a:digium:asterisk';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140344");
  script_version("$Revision: 13267 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-24 13:56:48 +0100 (Thu, 24 Jan 2019) $");
  script_tag(name:"creation_date", value:"2017-09-01 14:12:47 +0700 (Fri, 01 Sep 2017)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2017-14098");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Asterisk 'CVE-2017-14098' DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_asterisk_detect.nasl");
  script_mandatory_keys("Asterisk-PBX/Installed");

  script_tag(name:"summary", value:"Asterisk is prone to a denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A carefully crafted URI in a From, To or Contact header could cause
  Asterisk to crash.");

  script_tag(name:"affected", value:"Asterisk Open Source 13.15.0, 14.4.0.");

  script_tag(name:"solution", value:"Upgrade to Version 13.17.1, 14.6.1 or later.");

  script_xref(name:"URL", value:"http://downloads.asterisk.org/pub/security/AST-2017-007.html");

  exit(0);
}

include("host_details.inc");
include("revisions-lib.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_equal(version: version, test_version: "13.15.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "13.17.1");
  security_message(port: port, data: report);
  exit(0);
}

if (version_is_equal(version: version, test_version: "14.4.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "14.6.1");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);