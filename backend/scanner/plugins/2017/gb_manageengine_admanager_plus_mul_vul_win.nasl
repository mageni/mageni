###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_manageengine_admanager_plus_mul_vul_win.nasl 11874 2018-10-12 11:28:04Z mmartin $
#
# ManageEngine ADManager Plus Multiple Vulnerabilities (Windows)
#
# Authors:
# Tameem Eissa <tameem.eissa@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH
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

CPE = "cpe:/a:manageengine:admanager_plus";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107128");
  script_version("$Revision: 11874 $");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:28:04 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-01-17 16:11:25 +0530 (Tue, 17 Jan 2017)");
  script_name("ManageEngine ADManager Plus Multiple Vulnerabilities (Windows)");

  script_tag(name:"summary", value:"This host is installed with ManageEngine ADManager Plus and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Exploitation of these vulnerabilities could allow a remote attacker to execute arbitrary HTML and script code in a user's browser session in context of an affected site.");

  script_tag(name:"affected", value:"ManageEngine ADManager Plus up to and including version 6.5.40.");

  script_tag(name:"solution", value:"Upgrade to ManageEngine ADManager Plus 6.5.41 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/41082/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_manageengine_admanager_plus_detection.nasl");
  script_mandatory_keys("manageengine/admanager_plus/installed");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(isnull(port = get_app_port(cpe:CPE))) exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE)) exit(0);
Ver = infos['version'];
path = infos['location'];

if (version_is_less_equal(version: Ver, test_version:"6.5.40"))
{
  report = report_fixed_ver(installed_version:Ver, fixed_version:"6.5.41", install_path:path);
  security_message(data:report, port:port);
  exit(0);
}

exit(99);
