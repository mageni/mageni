###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_smarterstats_xss.nasl 12391 2018-11-16 16:12:15Z cfischer $
#
# SmarterStats Cross-Site Scripting Vulnerability
#
# Authors:
# Tameem Eissa <teissa@greenbone.net>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:smartertools:smarterstats";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107190");
  script_version("$Revision: 12391 $");
  script_cve_id("CVE-2017-14620");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_tag(name:"last_modification", value:"$Date: 2018-11-16 17:12:15 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2017-10-18 10:31:53 +0200 (Wed, 18 Oct 2017)");

  script_name("SmarterStats Cross-Site Scripting Vulnerability");

  script_tag(name:"summary", value:"SmarterStats is prone to a cross-site scripting vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability is due to rendering the Referer Field in IIS Logfiles and possibly other Field Names. This causes a stored DOM Xss attack.");

  script_tag(name:"impact", value:"A successful exploit could allow the attacker to execute arbitrary script code in the context of a trusted user.");

  script_tag(name:"affected", value:"SmarterStats 11.3.6347 and previous versions.");

  script_tag(name:"solution", value:"Update to 11.3.6480.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/42923/");
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_smarterstats_detect.nasl");
  script_mandatory_keys("smarterstats/installed");
  script_require_ports("Services/www", 8080);
  script_xref(name:"URL", value:"https://www.smartertools.com/smarterstats/downloads");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe:CPE))
  exit(0);

if (!ver = get_app_version(cpe: CPE, port: port))
  exit(0);

if( version_is_less(version:ver, test_version:"11.3.6480") ) {
  report = report_fixed_ver(installed_version:ver, fixed_version:"11.3.6480");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
