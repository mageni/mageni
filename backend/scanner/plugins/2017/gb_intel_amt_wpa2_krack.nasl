###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_intel_amt_wpa2_krack.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# Intel Active Management Technology WPA2 Key Reinstallation Vulnerabilities - KRACK
#
# Authors:
# Tameem Eissa <tameem.eissa@greenbone.net>
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

CPE = "cpe:/h:intel:active_management_technology";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107191");
  script_version("$Revision: 12106 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-10-19 13:48:56 +0700 (Thu, 19 Oct 2017)");
  script_tag(name:"cvss_base", value:"5.4");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2017-13077", "CVE-2017-13078", "CVE-2017-13080");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"Mitigation");

  script_name("Intel Active Management Technology WPA2 Key Reinstallation Vulnerabilities - KRACK");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_intel_amt_webui_detect.nasl");
  script_mandatory_keys("intel_amt/installed");

  script_tag(name:"summary", value:"WPA2 as used in Intel Active Management Technology is prone to multiple security weaknesses aka Key Reinstallation Attacks (KRACK)");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Intel AMT firmware versions 2.5.x, 2.6, 4.x, 6.x, 7.x, 8.x, 9.x, 10.x, and 11.0-11.8.");

  script_tag(name:"solution", value:"Intel is targeting an updated firmware release to System Manufacturers in early November 2017 to address the identified WPA2 vulnerabilities.
  Please contact System Manufacturers to ascertain availability of the updated firmware for their impacted systems.
  Until the firmware update is deployed, configuring Active Management Technology in TLS Mode to encrypt manageability
  network traffic is considered a reasonable mitigation for remote network man-in-the-middle or eavesdropping attacks.");

  script_xref(name:"URL", value:"https://www.intel.com/content/www/us/en/software/setup-configuration-software.html");
  script_xref(name:"URL", value:"https://security-center.intel.com/advisory.aspx?intelid=INTEL-SA-00101&languageid=en-fr");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "8"))
{
  report = report_fixed_ver(installed_version: version, fixed_version: "None Available");
  security_message(port: port, data: report);
  exit(0);
}

if (version =~ "^(8(\.[0-9]+)?|9(\.[0-9]+)?|10(\.[0-9]+)?)" || version_in_range(version: version, test_version: "11.0", test_version2: "11.8"))
{
  report = report_fixed_ver(installed_version: version, fixed_version: "See Vendor");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
