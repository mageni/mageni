###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mantisbt_xss_vuln_jan15.nasl 12818 2018-12-18 09:55:03Z ckuersteiner $
#
# MantisBT 'adm_config_report.php' Cross-Site Scripting Vulnerability - January15
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:mantisbt:mantisbt";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805236");
  script_version("$Revision: 12818 $");
  script_cve_id("CVE-2014-8986");
  script_bugtraq_id(71197);
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-12-18 10:55:03 +0100 (Tue, 18 Dec 2018) $");
  script_tag(name:"creation_date", value:"2015-01-08 18:58:08 +0530 (Thu, 08 Jan 2015)");
  script_name("MantisBT 'adm_config_report.php' Cross-Site Scripting Vulnerability - January15");

  script_tag(name:"summary", value:"This host is installed with
  MantisBT and is prone to cross-site scripting vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists as the
  adm_config_report.php script does not validate input when handling
  the config file option before returning it to users.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to execute arbitrary script code in a user's browser
  session within the trust relationship between their browser and the
  server.");

  script_tag(name:"affected", value:"MantisBT version 1.2.13 through 1.2.17");

  script_tag(name:"solution", value:"Upgrade to MantisBT version 1.2.18 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2014/11/15/1");
  script_xref(name:"URL", value:"https://github.com/mantisbt/mantisbt/commit/cabacdc291c251bfde0dc2a2c945c02cef41bf40");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("mantis_detect.nasl");
  script_mandatory_keys("mantisbt/detected");
  script_require_ports("Services/www", 80);
  script_xref(name:"URL", value:"http://www.mantisbt.org/download.php");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!manPort = get_app_port(cpe:CPE))
  exit(0);

if(!manVer = get_app_version(cpe:CPE, port:manPort))
  exit(0);

if(version_in_range(version:manVer, test_version:"1.2.13", test_version2:"1.2.17")) {
  report = report_fixed_ver(installed_version: manVer, fixed_version: "1.2.8");
  security_message(port: manPort, data: report);
  exit(0);
}

exit(99);
