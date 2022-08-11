###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_pandora_fms_auth_bypass_vuln.nasl 2015-06-23 10:58:30 Jun$
#
# Pandora FMS Authentication Bypass Vulnerability
#
# Authors:
# Deependra Bapna <bdeependra@secpod.com>
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

CPE = "cpe:/a:artica:pandora_fms";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805706");
  script_version("$Revision: 14184 $");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2019-03-14 14:29:04 +0100 (Thu, 14 Mar 2019) $");
  script_tag(name:"creation_date", value:"2015-06-23 10:58:30 +0530 (Tue, 23 Jun 2015)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Pandora FMS Authentication Bypass Vulnerability");

  script_tag(name:"summary", value:"This host is installed with Pandora
  FMS and is prone to authentication bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to the session is not being
  checked before the password is changed.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attacker to gain access to potentially sensitive information.");

  script_tag(name:"affected", value:"Pandora FMS 5.0 and 5.1.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
  Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove
  the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/37255");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_pandora_fms_detect.nasl");
  script_mandatory_keys("pandora_fms/installed");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!fmsPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!fmsVer = get_app_version(cpe:CPE, port:fmsPort)){
  exit(0);
}

if(version_is_equal(version:fmsVer, test_version:"5.0")||
   version_is_equal(version:fmsVer, test_version:"5.1"))
{
  report = 'Installed version: ' + fmsVer + '\n' +
           'Fixed version:     Not Available';

  security_message(port:fmsPort, data:report);
  exit (0);
}