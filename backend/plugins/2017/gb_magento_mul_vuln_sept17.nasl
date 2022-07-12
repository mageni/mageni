###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_magento_mul_vuln_sept17.nasl 11863 2018-10-12 09:42:02Z mmartin $
#
# Magento CMS Multiple Security Vulnerabilities
#
# Authors:
# Tameem Eissa <tameem.eissa@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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

CPE = "cpe:/a:magentocommerce:magento";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107186");
  script_version("$Revision: 11863 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 11:42:02 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-10-06 15:28:56 +0200 (Fri, 06 Oct 2017)");
  script_bugtraq_id(100869);

  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Magento CMS Multiple Security Vulnerabilities");

  script_tag(name:"summary", value:"Magento CMS is prone to multiple security vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Magento E-Commerce is prone to the following security vulnerabilities:

  - Multiple HTML-injection vulnerabilities

  - Multiple remote-code execution vulnerabilities

  - A directory-traversal vulnerability

  - An arbitrary file upload vulnerability

  - Multiple cross-site request forgery vulnerabilities

  - Multiple information-disclosure vulnerabilities

  - A security-bypass vulnerability");

  script_tag(name:"impact", value:"Attackers can exploit these issues to steal cookie-based authentication credentials,
      execute arbitrary scripts in the context of the web browser, execute arbitrary code in the context of the affected application,
      disclose sensitive information, elevate privileges, upload arbitrary files or bypass certain security restrictions and perform unauthorized actions.");
  script_tag(name:"affected", value:"Magento Commerce prior to 1.14.3.6");

  script_tag(name:"solution", value:"Update to Magento Commerce 1.14.3.6.");

  script_xref(name:"URL", value:"https://magento.com/security/patches/supee-10266");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100869");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");

  script_family("Web application abuses");

  script_dependencies("sw_magento_detect.nasl");
  script_mandatory_keys("magento/installed");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE)){
  exit(0);
}

if(!ver = get_app_version(cpe:CPE, port:port)){
  exit(0);
}

if(version_is_less(version:ver, test_version:"1.14.3.6")){
  report = report_fixed_ver(installed_version:ver, fixed_version:"1.14.3.6");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
