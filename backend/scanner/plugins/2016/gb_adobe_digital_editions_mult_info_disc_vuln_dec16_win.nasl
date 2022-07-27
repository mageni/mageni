###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_digital_editions_mult_info_disc_vuln_dec16_win.nasl 12455 2018-11-21 09:17:27Z cfischer $
#
# Adobe Digital Editions Multiple Vulnerabilities Dec16 (Windows)
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
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

CPE = "cpe:/a:adobe:digital_editions";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809834");
  script_version("$Revision: 12455 $");
  script_cve_id("CVE-2016-7888", "CVE-2016-7889");
  script_bugtraq_id(94879, 94880);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-11-21 10:17:27 +0100 (Wed, 21 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-12-15 11:09:34 +0530 (Thu, 15 Dec 2016)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Adobe Digital Editions Multiple Vulnerabilities Dec16 (Windows)");

  script_tag(name:"summary", value:"This host is installed with Adobe Digital Edition
  and is prone to multiple information disclosure vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The multiple flaws are due to,

  - An error when parsing XML external entities.

  - An unspecified error.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to obtain sensitive information and this may lead to further attacks.");

  script_tag(name:"affected", value:"Adobe Digital Edition prior to 4.5.3");
  script_tag(name:"solution", value:"Upgrade to Adobe Digital Edition version
  4.5.3 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/Digital-Editions/apsb16-45.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_adobe_digital_edition_detect_win.nasl");
  script_mandatory_keys("AdobeDigitalEdition/Win/Ver");
  script_xref(name:"URL", value:"http://www.adobe.com");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!digitalVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:digitalVer, test_version:"4.5.3"))
{
  report = report_fixed_ver(installed_version:digitalVer, fixed_version:"4.5.3");
  security_message(data:report);
  exit(0);
}
