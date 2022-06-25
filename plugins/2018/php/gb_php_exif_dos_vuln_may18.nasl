###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_php_exif_dos_vuln_may18.nasl 12391 2018-11-16 16:12:15Z cfischer $
#
# PHP 'ext/exif/exif.c' Denial of Service Vulnerability
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:php:php";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813625");
  script_version("$Revision: 12391 $");
  script_cve_id("CVE-2018-12882");
  script_bugtraq_id(104551);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 17:12:15 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-06-28 14:52:09 +0530 (Thu, 28 Jun 2018)");
  script_name("PHP 'ext/exif/exif.c' Denial of Service Vulnerability");

  script_tag(name:"summary", value:"The host is installed with php and is prone
  to denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an error in
  'exif_read_from_impl'  function in 'ext/exif/exif.c' script .");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to cause denial-of-service condition, denying service to legitimate users.");

  script_tag(name:"affected", value:"PHP versions 7.2.0 through 7.2.7.");

  script_tag(name:"solution", value:"Apply the patch from Reference links.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable"); ##It can result in FP for patched versions
  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=76409");
  script_xref(name:"URL", value:"http://sg2.php.net/downloads.php");
  script_xref(name:"URL", value:"https://bugs.php.net/patch-display.php?bug=76409&patch=avoid-double-free.patch&revision=1528027735");

  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_dependencies("gb_php_detect.nasl");
  script_mandatory_keys("php/installed");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(isnull(phport = get_app_port(cpe: CPE))){
  exit(0);
}

if(!infos = get_app_version_and_location(cpe:CPE, port:phport, exit_no_version:TRUE)) exit(0);
vers = infos['version'];
path = infos['location'];

if(version_in_range(version: vers, test_version: "7.2.0", test_version2: "7.2.7"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"Apply patch", install_path:path);
  security_message(port:phport, data:report);
  exit(0);
}
exit(0);
