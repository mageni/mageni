###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_pandora_fms_snmp_editor_xss_vuln.nasl 11872 2018-10-12 11:22:41Z cfischer $
#
# Pandora FMS SNMP Editor XSS Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.805709");
  script_version("$Revision: 11872 $");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:22:41 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-06-25 15:15:45 +0530 (Thu, 25 Jun 2015)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Pandora FMS SNMP Editor XSS Vulnerability");

  script_tag(name:"summary", value:"This host is installed with Pandora
  FMS and is prone to cross-site scripting vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Flaw is due to the SNMP trap editor does
  not validate input to the 'oid' and 'custom_oid' parameters before returning
  it to users.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary HTML and script code in a user's browser
  session within the trust relationship between their browser and the server.");

  script_tag(name:"affected", value:"Pandora FMS 5.1 SP1.");

  script_tag(name:"solution", value:"As a workaround provide secure restriction
  or filtering of the OID and customer OID input fields. Encode and parse the
  input field context to prevent persistent execution of script code through the
  vulnerable snmp editor module.");

  script_tag(name:"solution_type", value:"Workaround");

  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2015/Jan/84");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_pandora_fms_detect.nasl");
  script_mandatory_keys("pandora_fms/installed");
  script_require_ports("Services/www", 80);
  script_xref(name:"URL", value:"http://pandorafms.com");
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

if("5.1SP1" >< fmsVer)
{
  report = 'Installed version: ' + fmsVer + '\n' +
           'Fix:     Workaround';

  security_message(port:fmsPort, data:report);
  exit(0);
}
