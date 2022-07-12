###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_bloofoxCMS_44464.nasl 13960 2019-03-01 13:18:27Z cfischer $
#
# bloofoxCMS 'gender' Parameter SQL Injection Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
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

CPE = "cpe:/a:bloofox:bloofoxcms";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100877");
  script_version("$Revision: 13960 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-01 14:18:27 +0100 (Fri, 01 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-10-28 13:41:07 +0200 (Thu, 28 Oct 2010)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2010-4870");
  script_bugtraq_id(44464);

  script_name("bloofoxCMS 'gender' Parameter SQL Injection Vulnerability");

  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/44464");
  script_xref(name:"URL", value:"http://www.bloofox.com/cms/");
  script_xref(name:"URL", value:"http://www.htbridge.ch/advisory/sql_injection_in_bloofoxcms_registration_plugin.html");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("bloofoxCMS_detect.nasl");
  script_mandatory_keys("bloofoxcms/installed");

  script_tag(name:"summary", value:"bloofoxCMS is prone to an SQL-injection vulnerability because it fails to
  sufficiently sanitize user-supplied data before using it in an SQL query.");

  script_tag(name:"impact", value:"Exploiting this issue can allow an attacker to compromise the application,
  access or modify data, or exploit latent vulnerabilities in the underlying database.");

  script_tag(name:"affected", value:"bloofoxCMS 0.3.5 is vulnerable. Other versions may also be affected.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "0.4.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "0.4.0");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);