###############################################################################
# OpenVAS Vulnerability Test
#
# Magento 1.9.0.1 Cross-Site Scripting Vulnerability
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
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

CPE = "cpe:/a:magentocommerce:magento";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112055");
  script_version("2019-04-29T07:32:42+0000");
  script_cve_id("CVE-2014-9758");
  script_tag(name:"last_modification", value:"2019-04-29 07:32:42 +0000 (Mon, 29 Apr 2019)");
  script_tag(name:"creation_date", value:"2017-09-27 08:35:44 +0200 (Wed, 27 Sep 2017)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_name("Magento 1.9.0.1 Cross-Site Scripting Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("sw_magento_detect.nasl");
  script_mandatory_keys("magento/installed");

  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2015/12/05/4");

  script_tag(name:"summary", value:"Magento Web E-Commerce Platform is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Several Adobe Flash files that ship with Magento are vulnerable to DOM based Cross Site Scripting (XSS).");

  script_tag(name:"impact", value:"Successful exploitation of the flaw could allow a malicious attacker to gain control
  of a users session with the application or full control of the application if the targeted user has administrative privileges.");

  script_tag(name:"affected", value:"Magento E-Commerce version 1.9.0.1.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the
  disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to
  upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!ver = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_equal(version: ver, test_version: "1.9.0.1")) {
  report = report_fixed_ver(installed_version: ver, fixed_version: "WillNotFix");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);