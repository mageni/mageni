###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_digital_edition_info_disc_vuln_macosx.nasl 11867 2018-10-12 10:48:11Z cfischer $
#
# Adobe Digital Edition Information Disclosure Vulnerability (Mac OS X)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.804868");
  script_version("$Revision: 11867 $");
  script_cve_id("CVE-2014-8068");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:48:11 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-10-22 11:00:38 +0530 (Wed, 22 Oct 2014)");

  script_name("Adobe Digital Edition Information Disclosure Vulnerability (Mac OS X)");

  script_tag(name:"summary", value:"The host is installed with Adobe Digital
  Edition and is prone to information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists as sensitive data is
  insecurely transmitted to adelogs.adobe.com without any encryption.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to gain access to potentially sensitive information when sniffing the network.");

  script_tag(name:"affected", value:"Adobe Digital Edition version 4.0 on
  Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to Adobe Digital Edition version
  4.0.1 or later.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://the-digital-reader.com/2014/10/06/adobe-spying-users-collecting-data-ebook-libraries");
  script_xref(name:"URL", value:"http://arstechnica.com/security/2014/10/adobes-e-book-reader-sends-your-reading-logs-back-to-adobe-in-plain-text");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_adobe_digital_edition_detect_macosx.nasl");
  script_mandatory_keys("AdobeDigitalEdition/MacOSX/Version");
  script_xref(name:"URL", value:"http://www.adobe.com/products/digital-editions/download.html");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!ediVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_equal(version:ediVer, test_version:"4.0"))
{
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}
