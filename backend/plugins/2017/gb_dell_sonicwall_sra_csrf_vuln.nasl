###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dell_sonicwall_sra_csrf_vuln.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# Dell SonicWALL Secure Remote Access (SRA) CSRF Vulnerability
#
# Authors:
# INCIBE <ics-team@incibe.es>
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

CPE = "cpe:/o:dell:sonicwall_secure_remote_access_firmware";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106576");
  script_version("$Revision: 12106 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-02-08 12:16:13 +0700 (Wed, 08 Feb 2017)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2015-2248");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Dell SonicWALL Secure Remote Access (SRA) CSRF Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_dell_sonicwall_sma_detection.nasl");
  script_mandatory_keys("sonicwall/sra/detected");

  script_tag(name:"summary", value:"Dell SonicWALL Secure Remote Access (SRA) is prone to a cross-site request
forgery (CSRF) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability affects an unknown function of the file
/cgi-bin/editBookmark. The manipulation with an unknown input leads to a cross site request forgery
vulnerability.");

  script_tag(name:"impact", value:"The vulnerability enables someone to convince a user to create a malicious
bookmark that can then be used to steal account information associated with the bookmark.");

  script_tag(name:"affected", value:"Dell SonicWALL SRA versions 7.5.0.x and 8.0.0.x.");

  script_tag(name:"solution", value:"Upgrade to version 7.5.1.0-38sv, 8.0.0.1-16sv or newer.");

  script_xref(name:"URL", value:"https://support.software.dell.com/product-notification/151370?productName=SonicWALL%20SRA%20Series");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE))
  exit(0);

check_vers = ereg_replace(string: version, pattern: "-", replace: ".");

if (version_is_less(version: check_vers, test_version: "7.5.1.0.38sv")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.5.1.0-38sv");
  security_message(port: 0, data: report);
  exit(0);
}

if (version =~ "^8\.0\.0") {
  if (version_is_less(version: check_vers, test_version: "8.0.0.1.16sv")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "8.0.0.1-16sv");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(0);
