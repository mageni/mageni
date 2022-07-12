###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_drupal_mult_vuln_dec16_lin.nasl 11811 2018-10-10 09:55:00Z asteins $
#
# Drupal Multiple Vulnerabilities Dec16 (Linux)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################
CPE = 'cpe:/a:drupal:drupal';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810224");
  script_version("$Revision: 11811 $");
  script_cve_id("CVE-2016-9449", "CVE-2016-9450", "CVE-2016-9451", "CVE-2016-9452");
  script_bugtraq_id(94367);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-10 11:55:00 +0200 (Wed, 10 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-12-01 10:54:37 +0530 (Thu, 01 Dec 2016)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("Drupal Multiple Vulnerabilities Dec16 (Linux)");

  script_tag(name:"summary", value:"This host is running Drupal and is prone
  to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - An inconsistent naming of access query tags for taxonomy terms.

  - The user password reset form does not specify a proper cache context.

  - The confirmation forms allow external URLs to be injected.

  - An error in transliterate mechanism.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause a denial of service condition, obtain sensitive
  information, conduct cache poisoning attacks and conduct open redirect attacks.");

  script_tag(name:"affected", value:"Drupal core 7.x versions prior to 7.52
  and 8.x versions prior to 8.2.3 on Linux");

  script_tag(name:"solution", value:"Upgrade to version 7.52 or 8.2.3 or newer.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.drupal.org/SA-CORE-2016-005");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("drupal_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("drupal/installed", "Host/runs_unixoide");
  script_require_ports("Services/www", 80);
  script_xref(name:"URL", value:"https://www.drupal.org");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!drupalPort= get_app_port(cpe:CPE)){
  exit(0);
}

if(!drupalVer = get_app_version(cpe:CPE, port:drupalPort, version_regex:"^[0-9]\.[0-9]+")){
  exit(0);
}

if(drupalVer =~ "^(8\.)")
{
  if(version_in_range(version:drupalVer, test_version:"8.0", test_version2:"8.2.2"))
  {
     VULN = TRUE;
     fix = "8.2.3";
  }
}
else if(drupalVer =~ "^(7\.)")
{
  if(version_in_range(version:drupalVer, test_version:"7.0", test_version2:"7.51"))
  {
     VULN = TRUE;
     fix = "7.52";
  }
}

if(VULN)
{
  report = report_fixed_ver(installed_version:drupalVer, fixed_version:fix);
  security_message(data:report, port:drupalPort);
  exit(0);
}
