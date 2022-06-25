###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hp_smh_cmd_inj_vuln.nasl 11883 2018-10-12 13:31:09Z cfischer $
#
# HP System Management Homepage Command Injection Vulnerability-July2013
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
CPE = "cpe:/a:hp:system_management_homepage";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803846");
  script_version("$Revision: 11883 $");
  script_cve_id("CVE-2013-3576");
  script_bugtraq_id(60471);
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:31:09 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-07-30 13:30:42 +0530 (Tue, 30 Jul 2013)");
  script_name("HP System Management Homepage Command Injection Vulnerability-July2013");

  script_tag(name:"summary", value:"This host is running HP System Management Homepage (SMH) and is prone to
command injection  vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"solution", value:"Upgrade to version 7.2.2, or later.");
  script_xref(name:"URL", value:"http://h18013.www1.hp.com/products/servers/management/agents/index.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"insight", value:"The flaw is triggered when the ginkgosnmp.inc script uses the last path
segment of the current requested URL path in an exec call without properly
sanitizing the content.");
  script_tag(name:"affected", value:"HP System Management Homepage (SMH) version 7.2.1.3 and prior");
  script_tag(name:"impact", value:"Successful exploitation will allow an authenticated remote attacker to execute
arbitrary commands.");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/26420");
  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/735364");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_hp_smh_detect.nasl");
  script_mandatory_keys("HP/SMH/installed");
  script_require_ports("Services/www", 2381);
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

if(! port = get_app_port(cpe:CPE)) exit(0);

if(! version = get_app_version(cpe:CPE, port:port)) exit(0);

if(version_is_less_equal(version:version, test_version:"7.2.1.3"))
{
  security_message(port);
  exit(0);
}
